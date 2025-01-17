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
	: ar_hrd(htons(ARPHRD_ETHER)), ar_pro(htons(L2_impl::ether_header::ETHERTYPE_IP)), ar_hln(6 * sizeof(u_char)),
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

/************************************************************************/
/*							L2_ARP::llinfo_arp				            */
/************************************************************************/

L2_ARP::llinfo_arp::llinfo_arp(bool permanent)
	: la_asked(0), la_flags(0), la_timeStamp(static_cast<unsigned long long>(permanent ? 0 : floor(GetTickCount64()))),
	la_hold(), la_hold_it(), la_mac("") { }

L2_ARP::llinfo_arp::llinfo_arp(const mac_addr& la_mac, bool permanent) : llinfo_arp(permanent) { update(la_mac); }

L2_ARP::llinfo_arp::~llinfo_arp() { pop(); }

void L2_ARP::llinfo_arp::pop()
{
	if (la_hold != nullptr) {
		la_hold.reset(new std::vector<byte>());
		la_hold_it = std::vector<byte>::iterator();
	}
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