#include <list>
#include <iomanip>

#include "../L3/L3.h"
#include "L2.h"
#include "L2_ARP_impl.h"

#include <algorithm>

/************************************************************************/
/*                    L2_ARP_impl::ArpCache						        */
/************************************************************************/

L2_ARP_impl::ArpCache::ArpCache(const unsigned long arp_maxtries, const unsigned int arpt_down)
	: arp_maxtries(arp_maxtries), arpt_down(arpt_down) { }

void L2_ARP_impl::ArpCache::cleanup()
{
	u_long oldest;
	unsigned long long oldestTime(0);
	for (auto it = begin(); it != end();) {
		if (!it->second->valid())
			erase(it);
		else if (oldestTime < it->second->getLaTimeStamp()) {
			oldest = it->first;
			oldestTime = (it)->second->getLaTimeStamp();
		}
		it++;
	}

	if (size() == arp_maxtries)
		erase(find(oldest));
	else if (size() > arp_maxtries)
		throw std::runtime_error("ArpCache:: Too Many elements inserted to ARP Cache!");
}

L2_ARP_impl::ArpCache::mapped_type& L2_ARP_impl::ArpCache::operator[] (const key_type& k) {
	if (size() >= arp_maxtries)
		cleanup();
	return _Myt::operator[](k);
}

L2_ARP_impl::ArpCache::mapped_type& L2_ARP_impl::ArpCache::operator[] (key_type&& k) {
	if (size() >= arp_maxtries)
		cleanup();
	return _Myt::operator[](k);
}

L2_ARP_impl::ArpCache::iterator L2_ARP_impl::ArpCache::find(const key_type& _Keyval) {
	iterator it(_Myt::find(_Keyval));
	if (it != end())
		if (it->second->valid())
			return it;
		else
			erase(it);
	return end();
}

/************************************************************************/
/*							 L2_ARP_impl						        */
/************************************************************************/

// Constructor
L2_ARP_impl::L2_ARP_impl(inet_os& inet, const unsigned long arp_maxtries, const int arpt_down)
	: L2_ARP(inet, arp_maxtries, arpt_down), arpcache(ArpCache(arp_maxtries, arpt_down)) { }

void L2_ARP_impl::insertPermanent(const u_long ip, const mac_addr& la_mac) {
	arpcache[ip] = std::shared_ptr<L2_ARP::llinfo_arp>(new L2_ARP::llinfo_arp(la_mac, true));
}

void L2_ARP_impl::arpwhohas(const struct in_addr& addr) { return arprequest(addr.s_addr); }

void L2_ARP_impl::arprequest(const u_long& tip)
{
	std::vector<byte>::iterator it;
	std::shared_ptr<std::vector<byte>> m(ether_arp::make_arp_request(tip, inet.nic()->ip_addr().s_addr, "", inet.nic()->mac(), it));

	struct sockaddr sa;
	struct L2::ether_header* eh = reinterpret_cast<struct L2::ether_header*>(sa.sa_data);
	eh->ether_dhost = inet.nic()->etherbroadcastaddr();
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */
	sa.sa_family = AF_UNSPEC;
	inet.datalink()->ether_output(m, it, &sa, nullptr);
}

L2_ARP_impl::mac_addr* L2_ARP_impl::arpresolve(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, short m_flags, struct sockaddr* dst)
{
	 /*
	  *	Get pointer to llinfo_arp structure:
	  *	The destination address is a unicast address. If a pointer to a routing table entry is
	  *	passed by the caller, la is set to the corresponding llinfo_arp structure. Otherwise
	  *	arplookup searches the routing table for the specified IP address. The second argument
	  *	is 1, telling arplookup to create the entry if it doesn't already exist; the third
	  *	argument is 0, which means don't look for a proxy ARP entry.
	  */
	struct in_addr& sin(reinterpret_cast<struct sockaddr_in*>(dst)->sin_addr);
	std::shared_ptr<L2_ARP::llinfo_arp>& la(arplookup(sin.s_addr, true));

	/*
	 *	If either rt or la are null pointers, one of the allocations failed, since arplookup
	 *	should have created an entry if one didn't exist. An error message is logged, the packet
	 *	released, and the function returns 0.
	 */
	if (la)
	{
		/*
		 *	Even though an ARP entry is located, it must be checked for validity. The entry is valid if the entry is
		*	permanent (the expiration time is 0) or the expiration time is greater than the current time
		*	If the entry is valid, the address is resolved; otherwise, try to resolve.
		*/
		if (la->getLaMac() != "")
			return &la->getLaMac();

		/*
		 *	At this point an ARP entry exists but it does not contain a valid Ethernet address. An ARP request
		*	must be sent. First the pointer to the Packet is saved in la_hold, after releasing any Packet
		*	that was already pointed to by la_hold. This means that if multiple IP datagrams are sent quickly
		*	to a given destination, and an ARP entry does not already exist for the destination, during the
		*	time it takes to send an ARP request and receive a reply only the last datagram is held, and all
		*	prior ones are discarded.
		*
		*	An example that generates this condition is NFS. If NFS sends an 8500-byte IP datagram that is
		*	fragmented into six IP fragments, and if all six fragments are sent by ip_output to ether_output
		*	in the time it takes to send an ARP request and receive a reply, the first five fragments are
		*	discarded and only the final fragment is sent when the reply is received. This in turn causes an
		*	NFS timeout, and a retransmission of all six fragments.
		*
		* There is an arptab entry, but no Ethernet address response yet.  Replace the held mbuf with this
		* latest one.
		*/
		la->push(m, it);

		/*	RFC 1122 requires ARP to avoid sending ARP requests to a given destination at a high rate when a
		*	reply is not received. The technique used by Net/3 to avoid ARP flooding is as follows:
		*
		*	•	Net/3 never sends more than one ARP request in any given second to a destination.
		*
		*	•	If a reply is not received after five ARP requests (i.e., after about 5 seconds), the RTF_REJECT
		*		flag in the routing table is set and the expiration time is set for 20 seconds in the future.
		*		This causes ether_output to refuse to send IP datagrams to this destination for 20 seconds,
		*		returning EHOSTDOWN or EHOSTUNREACH instead (Figure 4.15).
		*
		*	•	After the 20-second pause in ARP requests, arpresolve will send ARP requests to that destination
		*		again. 
		*
		*	If the expiration time is nonzero (i.e., this is not a permanent entry) the RTF_REJECT flag is cleared,
		*	in case it had been set earlier to avoid flooding. The counter la_asked counts the number of consecutive
		*	times an ARP request has been sent to this destination. If the counter is 0 or if the expiration time
		*	does not equal the current time (looking only at the seconds portion of the current time), an ARP request
		*	might be sent. This comparison avoids sending more than one ARP request during any second. The expiration
		*	time is then set to the current time in seconds (i.e., the millisecond portion, time is ignored).
		*
		*	The counter is compared to the limit of 5 (arp_maxtries) and then incremented. If the value was less
		*	than 5, arpwhohas sends the request. If the request equals 5, however, ARP has reached its limit: the
		*	RTF_REJECT flag is set, the expiration time is set to 20 seconds in the future, and the counter
		*	la_asked is reset to 0.	*/
		if (la->clearToSend(getArpMaxtries(), getArptDown()))
			arpwhohas(sin);
	}

	return nullptr;
}

std::shared_ptr<L2_ARP::llinfo_arp> L2_ARP_impl::arplookup(const u_long addr, bool create)
{
	ArpCache::iterator it(arpcache.find(addr));
	if (it != arpcache.end())
		return it->second;
	else if (create)
		return arpcache[addr] = std::shared_ptr < L2_ARP::llinfo_arp >(new L2_ARP::llinfo_arp());
	return nullptr;
}

/*
 *	in_arpinput Function:
 *	This function is called by arpintr to process each received ARP request or ARP reply.
 *	While ARP is conceptually simple, numerous rules add complexity to the implementation.
 *	The following two scenarios are typical:
 *		1.	If a request is received for one of the host's IP addresses, a reply is sent. This is
 *			the normal case of some other host on the Ethernet wanting to send this host a
 *			packet. Also, since we're about to receive a packet from that other host, and
 *			we'll probably send a reply, an ARP entry is created for that host (if one doesn't
 *			already exist) because we have its IP address and hard\vare address. This optimization
 *			avoids another ARP exchange when the packet is received from the other host.
 *		2.	If a reply is received in response to a request sent by this host, the corresponding
 *			ARP entry is now complete (the hardware address is known). The other host's
 *			hardware address is stored in the sockaddr_dl structure and any queued
 *			packet for that host can now be sent. Again, this is the normal case.
 *	ARP requests are normally broadcast so each host sees all ARP requests on the Ethernet,
 *	even those requests for which it is not the target. Recall from arprequest that when a
 *	request is sent, it contains the sender's IP address and hardware address. This allows the
 *	following tests also to occur.
 *		3.	If some other host sends a request or reply with a sender IP address that equals
 *			this host's IP address, one of the two hosts is misconfigured. Net/3 detects this
 *			error and logs a message for the administrator. (We say "request or reply" here
 *			because in_arpinput doesn't examine the operation type. But ARP replies are
 *			normally unicast, in which case only the target host of the reply receives the reply.)
 *		4.	If this host receives a request or reply from some other host for which an ARP
 *			entry already exists, and if the other host's hard\vare address has changed, the
 *			hardware address in the ARP entry is updated accordingly. This can happen if
 *			the other host is shut down and then rebooted with a different Ethernet interface
 *			(hence a different hardware address) before its ARP entry times out. The
 *			use of this technique, along with the other host sending a gratuitous ARP
 *			request when it reboots, prevents this host from being unable to communicate
 *			with the other host after the reboot because of an ARP entry that is no longer
 *			valid.
 *		5.	This host can be configured as a proxy ARP server. This means it responds to
 *			ARP requests for some other host, supplying the other host's hardware address
 *			in the reply. The host whose hardware address is supplied in the proxy ARP
 *			reply must be one that is able to forward IP datagrams to the host that is the target
 *			of the ARP request. Section 4.6 of Volume 1 discusses proxy ARP.
 *			A Net/3 system can be configured as a proxy ARP server. These ARP entries
 *			are added with the arp command, specifying the IP address, hardware address,
 *			and the keyword pub. We'll see the support for this in Figure 21.20 and we
 *			describe it in Section 21.12.
 *
* ARP for Internet protocols on 10 Mb/s Ethernet.
* Algorithm is that given in RFC 826.
* In addition, a sanity check is performed on the sender
* protocol address, to catch impersonators.
* We no longer handle negotiations for use of trailer protocol:
* Formerly, ARP replied for protocol type ETHERTYPE_TRAIL sent
* along with IP replies if we wanted trailers sent to us,
* and also sent them in response to IP replies.
* This allowed either end to announce the desire to receive
* trailer packets.
* We no longer reply to requests for ETHERTYPE_TRAIL protocol either,
* but formerly didn't normally send requests.
*/
void L2_ARP_impl::in_arpinput(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it) {
	struct ether_arp* ea(reinterpret_cast<struct ether_arp*>(&m->data()[it - m->begin()]));
	struct in_addr* isaddr(reinterpret_cast<struct in_addr*>(ea->arp_spa));
	struct in_addr* itaddr(reinterpret_cast<struct in_addr*>(ea->arp_tpa));
	bool out(false);
	std::shared_ptr<L2_ARP::llinfo_arp> la;

	if (ea->arp_sha == inet.nic()->mac())
		out = true;

	/*
	 *	If the sender's hardware address is the Ethernet broadcast address, this is an error. The error is printed and
	 *	the packet is discarded.
	 */
	else if (ea->arp_sha == inet.nic()->etherbroadcastaddr()) {
		out = true;
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "arp: ether address is broadcast for IP address " << inet_ntoa(*isaddr) << "!" << std::endl;
	}

	else if ((*isaddr).s_addr == inet.nic()->ip_addr().s_addr) {
		*itaddr = inet.nic()->ip_addr();
		std::lock_guard<std::mutex> lock(inet.print_mutex);
		std::cout << "arp: duplicate IP address " << inet_ntoa(*isaddr) << "! sent from Ethernet address : " << ea->arp_sha << std::endl;
	}

	/*
	*	arplookup searches the ARP cache for the sender's IP address (isaddr). The second argument is 1 if the target
	*	IP address equals myaddr (meaning create a new entry if an entry doesn't exist), or not 0 otherwise (do not create
	*	a new entry). An entry is always created for the sender if this host is the target; otherwise the host is
	*	processing a broadcast intended for some other target, so it just looks for an existing entry for the sender.
	*	As mentioned earlier, this means that if a host receives an ARP request for itself from another host, an ARP
	*	entry is created for that other host on the assumption that, since another host is about to send us a packet,
	*	we'll probably send a reply. The return value is a pointer to a PMY_LLINFO_ARP structure, or a null pointer if an
	*	entry is not found or created.
	*/
	else if (la = arplookup((*isaddr).s_addr, (*itaddr).s_addr == inet.nic()->ip_addr().s_addr)) {
		/*
		*	If the link-level address length (sdl_alen) is nonzero (meaning that an existing entry
		*	is being referenced and not a new entry that was just created), the link-level address
		*	is compared to the sender's hardware address. If they are different, the sender's
		*	Ethernet address has changed. This can happen if the sending host is shut down, its
		*	Ethernet interface card replaced, and it reboots before the ARP entry times out. While
		*	not common, this is a possibility that must be handled. An informational message is
		*	printed and the code continues, which will update the hardware address with its new value.
		*/
		if (la->getLaMac() != "" && la->getLaMac() != ea->arp_sha) {
			std::lock_guard<std::mutex> lock(inet.print_mutex);
			std::cout << "arp info overwritten for " << inet_ntoa(*isaddr) << " by " << ea->arp_sha << std::endl;
		}

		la->update(ea->arp_sha);

		/*	If ARP is holding onto a Packet awaiting ARP resolution of that host's hardware address
		*	(the la_hold pointer), the Packet is passed. Since this Packet was being held by ARP the
		*	destination address must be on a local Ethernet so the function is ether_output. This
		*	function again calls arpresolve, but the hardware address was just filled in, allowing
		*	the Packet to be sent.	*/
		if (!la->empty()) {
			struct sockaddr sa;
			struct L2::ether_header* eh(reinterpret_cast<struct L2::ether_header*>(sa.sa_data));
			eh->ether_shost = inet.nic()->mac();
			eh->ether_dhost = la->getLaMac();
			eh->ether_type = L2::ether_header::ETHERTYPE_IP;		/* if_output will swap */
			sa.sa_family = AF_UNSPEC;
			inet.datalink()->ether_output(la->front(), la->front_it(), &sa, nullptr);
			la->pop();
		}
	}

	int op(ntohs(ea->arp_op()));
	if (op != ether_arp::arphdr::ARPOP_REQUEST || out)
		return;

	/*
	*	If the target IP address equals myIPaddr, this host is the target of the request. The source hardware
	*	address is copied into the target hardware address (i.e., whoever sent it becomes the target) and
	*	the Ethernet address of the interface is copied from myMACaddr into the source hardware address.
	*	The remainder of the ARP reply is constructed after.
	*/
	if ((*itaddr).s_addr == inet.nic()->ip_addr().s_addr)

		/*
		 *	I am the target so construct the ARP reply. The sender and target hardware addresses have
		 *	been filled in. The sender and target IP addresses are now swapped. The	target IP address
		 *	is contained in itaddr
		 */
		return SendArpReply(*isaddr, *itaddr, ea->arp_sha, inet.nic()->mac());

	/* I am the target */
	ea->arp_tha = ea->arp_sha;
	ea->arp_sha = inet.nic()->mac();

	memcpy(ea->arp_tpa, ea->arp_spa, sizeof(ea->arp_spa));
	memcpy(ea->arp_spa, &itaddr, sizeof(ea->arp_spa));

	ea->arp_op() = htons(ether_arp::arphdr::ARPOP_REPLY);
	ea->arp_pro() = htons(L2::ether_header::ETHERTYPE_IP); /* let's be sure! */

	struct sockaddr sa;
	struct L2::ether_header* eh(reinterpret_cast<struct L2::ether_header*>(sa.sa_data));
	eh->ether_shost = inet.nic()->mac();
	eh->ether_dhost = ea->arp_tha;
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */

	sa.sa_family = AF_UNSPEC;
	return inet.datalink()->ether_output(m, it, &sa, nullptr);
}

void L2_ARP_impl::SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const
{
	std::vector<byte>::iterator it;
	std::shared_ptr<std::vector<byte>> m(ether_arp::make_arp_reply(itaddr.s_addr, isaddr.s_addr, hw_tgt, hw_snd, it));

	struct sockaddr sa;
	struct L2::ether_header* eh(reinterpret_cast<struct L2::ether_header*>(sa.sa_data));
	eh->ether_shost = hw_snd;
	eh->ether_dhost = hw_tgt;
	eh->ether_type = L2::ether_header::ETHERTYPE_ARP;		/* if_output will swap */

	sa.sa_family = AF_UNSPEC;
	inet.datalink()->ether_output(m, it, &sa, nullptr);
}