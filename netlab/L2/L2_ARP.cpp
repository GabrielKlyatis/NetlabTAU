#include <list>
#include <iomanip>

#include "../L3/L3.h"
#include "L2.h"
#include "L2_ARP.h"

#include <algorithm>
/************************************************************************/
/*                    L2_ARP::ether_arp::arphdr			                */
/************************************************************************/

L2_ARP::ether_arp::arphdr::arphdr(ARPOP_ op)
	: ar_hrd(htons(ARPHRD_ETHER)), ar_pro(htons(L2::ether_header::ETHERTYPE_IP)), ar_hln(6 * sizeof(u_char)),
	ar_pln(4 * sizeof(u_char)), ar_op(htons(op)) { }

std::string L2_ARP::ether_arp::arphdr::ar_op_format() const
{
	switch (ar_op)
	{
	case L2_ARP::ether_arp::arphdr::ARPOP_REQUEST:
		return "ARPOP_REQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REPLY:
		return "ARPOP_REPLY";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REVREQUEST:
		return "ARPOP_REVREQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_REVREPLY:
		return "ARPOP_REVREPLY";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_INVREQUEST:
		return "ARPOP_INVREQUEST";
		break;
	case L2_ARP::ether_arp::arphdr::ARPOP_INVREPLY:
		return "ARPOP_INVREPLY";
		break;
	default:
		return "";
		break;
	}
}

std::string L2_ARP::ether_arp::arphdr::hw_addr_format() const
{
	switch (ar_hrd)
	{
	case ARPHRD_ETHER:
		return "ARPHRD_ETHER";
		break;
	case ARPHRD_FRELAY:
		return "ARPHRD_FRELAY";
		break;
	default:
		return "NOT_SET";
		break;
	}
}

std::ostream& operator<<(std::ostream& out, const struct L2_ARP::ether_arp::arphdr& ea_hdr)
{
	std::ios::fmtflags f(out.flags());
	out << "HardwareType = " << ea_hdr.hw_addr_format() <<
		"(= 0x" << std::setfill('0') << std::setw(2) << std::hex << ea_hdr.ar_hrd << ")" <<
		" , ProtocolType = 0x" << std::setw(2) << std::hex << ea_hdr.ar_pro <<
		" , HardwareAddressLength  = " << std::dec << static_cast<u_char>(ea_hdr.ar_hln) <<
		" , ProtocolAddressLength  = " << std::dec << static_cast<u_char>(ea_hdr.ar_pln) <<
		" , Operation = " << ea_hdr.ar_op_format() <<
		"(= 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<u_short>(ea_hdr.ar_op) << ")";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                    L2_ARP::ether_arp					                */
/************************************************************************/

L2_ARP::ether_arp::ether_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, arphdr::ARPOP_ op)
	: ea_hdr(op), arp_sha(saddr), arp_tha(taddr)
{
	std::memcpy(arp_spa, &sip, sizeof(arp_spa));
	std::memcpy(arp_tpa, &tip, sizeof(arp_tpa));
}

std::ostream& operator<<(std::ostream& out, const struct L2_ARP::ether_arp& ea)
{
	std::ios::fmtflags f(out.flags());
	out << "< ARP (" << static_cast<uint32_t>(sizeof(struct	L2_ARP::ether_arp)) <<
		" bytes) :: " << ea.ea_hdr <<
		" , SenderHardwareAddress = " << ea.arp_sha <<
		" , SenderProtocol Address = " << inet_ntoa(*reinterpret_cast<struct in_addr*>(const_cast<u_char*>(ea.arp_spa)));
	out << " , TargetHardwareAddress = " << ea.arp_tha <<
		" , TargetProtocol Address = " << inet_ntoa(*reinterpret_cast<struct in_addr*>(const_cast<u_char*>(ea.arp_tpa))) <<
		" , >";
	out.flags(f);
	return out;
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator& it, arphdr::ARPOP_ op)
{
	/*
	*	Allocate and Initialize mbuf
	*	A packet header mbuf is allocated and the two length fields are set. MH_ALIGN
	*	allows room for a 28-byte ether_arp structure at the end of the mbuf, and sets the
	*	m_data pointer accordingly. The reason for moving this structure to the end of the
	*	mbuf is to allow ether_output to prepend the 14-byte Ethernet header in the same
	*	mbuf.
	*/
	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(sizeof(struct L2::ether_header) + sizeof(struct L2_ARP::ether_arp)));
	if (m == nullptr)
		throw std::runtime_error("make_arp_request failed! allocation failed!");

	/*
	* As above, for mbufs allocated with m_gethdr/MGETHDR
	* or initialized by M_COPY_PKTHDR.
	*/
	it = m->begin() + sizeof(struct L2::ether_header);
	memcpy(&m->data()[it - m->begin()], &struct L2_ARP::ether_arp(tip, sip, taddr, saddr, op), sizeof(struct L2_ARP::ether_arp));
	return m;
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp_request(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator& it)
{
	return make_arp(tip, sip, taddr, saddr, it);
}

std::shared_ptr<std::vector<byte>> L2_ARP::ether_arp::make_arp_reply(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator& it)
{
	return make_arp(tip, sip, taddr, saddr, it, ether_arp::arphdr::ARPOP_REPLY);
}

/************************************************************************/
/*							L2_ARP::llinfo_arp				            */
/************************************************************************/

L2_ARP::llinfo_arp::llinfo_arp(bool permanent)
	: la_asked(0), la_flags(0), la_timeStamp(static_cast<unsigned long long>(permanent ? 0 : floor(GetTickCount64()))),
	la_hold(), la_hold_it(), la_mac("") { }

L2_ARP::llinfo_arp::llinfo_arp(const mac_addr& la_mac, bool permanent) : llinfo_arp(permanent) { update(la_mac); }

L2_ARP::llinfo_arp::~llinfo_arp() { pop(); }

bool L2_ARP::llinfo_arp::valid() const
{
	unsigned long long cmp(static_cast<unsigned long long>(floor(GetTickCount64())));
	return true; // REVERT
	//return la_timeStamp == 0 || (cmp > la_timeStamp && cmp < MAX_TIME_STAMP + la_timeStamp);
}

L2_ARP::mac_addr& L2_ARP::llinfo_arp::getLaMac() { return la_mac; }

unsigned long long L2_ARP::llinfo_arp::getLaTimeStamp() const { return la_timeStamp; }

bool L2_ARP::llinfo_arp::clearToSend(const unsigned long arp_maxtries, const unsigned int arpt_down)
{
	if (la_timeStamp) {
		la_flags &= ~L3::rtentry::RTF_REJECT;
		if (la_asked == 0 || (la_timeStamp != floor(GetTickCount64()))) {
			la_timeStamp = static_cast<unsigned long long>(std::floor(GetTickCount64()));
			if (la_asked++ < arp_maxtries)
				return true;
			else {
				la_flags |= L3::rtentry::RTF_REJECT;
				la_timeStamp += arpt_down;
				la_asked = 0;
			}
		}
	}
	return false;
}

void L2_ARP::llinfo_arp::pop()
{
	if (la_hold != nullptr) {
		la_hold.reset(new std::vector<byte>());
		la_hold_it = std::vector<byte>::iterator();
	}
}

void L2_ARP::llinfo_arp::push(std::shared_ptr<std::vector<byte>> hold, const std::vector<byte>::iterator hold_it)
{
	pop();
	la_hold = hold;
	la_hold_it = hold_it;
}

std::shared_ptr<std::vector<byte>> L2_ARP::llinfo_arp::front() const { return la_hold; }

std::vector<byte>::iterator& L2_ARP::llinfo_arp::front_it() { return la_hold_it; }

bool L2_ARP::llinfo_arp::empty() const {
	return la_hold ? la_hold->empty() : true;
}

void L2_ARP::llinfo_arp::update(const mac_addr la_mac)
{
	/*	The sender's hardware address is copied into a UCHAR array.	*/
	this->la_mac = la_mac;

	/*	When the sender's hardware address is resolved, the following steps occur. If the expiration
	*	time is nonzero, it is reset to the current time in the future. This test exists because
	*	the arp command can create permanent entries: entries that never time out. These entries
	*	are marked with an expiration time of 0. When an ARP request is sent (i.e., for a non
	*	permanent ARP entry) the expiration time is set to the current time, which is nonzero. */
	if (la_timeStamp != 0)
		la_timeStamp = GetTickCount64();

	/*	The RTF_REECT flag is cleared and the la_asked counter is set to 0. We'll see that these
	*	last two steps are used in arpresolve to avoid ARP flooding.	*/
	la_flags &= ~L3::rtentry::RTF_REJECT;
	la_asked = 0;
}