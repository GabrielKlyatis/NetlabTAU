/*!
	\file	L3_impl.cpp

	\author	Tom Mahler, contact at tommahler@gmail.com

	\brief	Implements the L3 class.
*/

#pragma once

/*!
	\def	NETLAB_L3_FORWARDING
	To enable IP forwarding, currently disabled.
*/
#define NETLAB_L3_FORWARDING
#ifdef NETLAB_L3_FORWARDING
#undef NETLAB_L3_FORWARDING
#endif

/*!
	\def	NETLAB_L3_OPTIONS
	To enable IP options, currently disabled.
*/
#define NETLAB_L3_OPTIONS
#ifdef NETLAB_L3_OPTIONS
#undef NETLAB_L3_OPTIONS
#endif

/*!
	\def	NETLAB_L3_MULTICAST
	To enable IP multi casting, currently disabled.
*/
#define NETLAB_L3_MULTICAST
#ifdef NETLAB_L3_MULTICAST
#undef NETLAB_L3_MULTICAST
#endif

/*!
	\def	NETLAB_L3_FRAGMENTATION
	To enable IPfragmentation, currently disabled.
*/
#define NETLAB_L3_FRAGMENTATION
#ifdef NETLAB_L3_FRAGMENTATION
#undef NETLAB_L3_FRAGMENTATION
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <iomanip>
#include <algorithm>

#include "L3_impl.h"
#include "../L2/L2.h"
#include "../L1/NIC.h"

/************************************************************************/
/*                         ip_output_args                               */
/************************************************************************/

L3_impl::ip_output_args::ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it,
	std::shared_ptr<std::vector<byte>>& opt, struct L3_impl::route* ro, int flags, struct  L3_impl::ip_moptions* imo)
	: m(m), it(it), opt(opt), ro(ro), flags(flags), imo(imo) { }

/************************************************************************/
/*                         rt_metrics	                                */
/************************************************************************/

L3_impl::rt_metrics::rt_metrics()
	: rmx_locks(0), rmx_mtu(0), rmx_hopcount(0), rmx_expire(0),
	rmx_recvpipe(0), rmx_sendpipe(0), rmx_ssthresh(0), rmx_rtt(0),
	rmx_rttvar(0), rmx_pksent(0) { }

/************************************************************************/
/*                         radix_node	                                */
/************************************************************************/

L3_impl::radix_node::radix_node()
	: rn_mklist(nullptr), rn_p(nullptr), rn_b(0), rn_bmask(0), rn_flags(0)
{
	rn_u.rn_leaf.rn_Dupedkey = nullptr;
	rn_u.rn_leaf.rn_Key = nullptr;
	rn_u.rn_leaf.rn_Mask = nullptr;
	rn_u.rn_node.rn_L = nullptr;
	rn_u.rn_node.rn_R = nullptr;
	rn_u.rn_node.rn_Off = 0;
}

/************************************************************************/
/*                         L3_impl::rtentry	                                */
/************************************************************************/

L3_impl::rtentry::rtentry(struct sockaddr* dst, int report, inet_os* inet)
	: rt_gateway(nullptr), rt_flags(0), rt_refcnt(0), rt_use(0), rt_ifp(inet), rt_genmask(nullptr), rt_llinfo(nullptr), rt_gwroute(nullptr)
{
#ifdef NETLAB_L3_FORWARDING
	struct rtentry* rt;
	struct rtentry* newrt = nullptr;
	struct rt_addrinfo info;
	inet_t::splnet();
	int err = 0, msgtype = RTM_MISS;
	struct radix_node* rn;
	struct radix_node_head* rnh = rt_tables[dst->sa_family];
	if (rnh && (rn = rnh->rnh_matchaddr((caddr_t)dst, rnh)) && ((rn->rn_flags & RNF_ROOT) == 0)) {
		newrt = rt = (struct rtentry*)rn;
		if (report && (rt->rt_flags & RTF_CLONING)) {
			err = rtrequest(RTM_RESOLVE, dst, SA(0), SA(0), 0, &newrt);
			if (err) {
				newrt = rt;
				rt->rt_refcnt++;
				goto miss;
			}
			if ((rt = newrt) && (rt->rt_flags & RTF_XRESOLVE)) {
				msgtype = RTM_RESOLVE;
				goto miss;
			}
		}
		else
			rt->rt_refcnt++;
	}
	else {
	miss:
		if (report) {
			/*bzero((caddr_t)&info, sizeof(info));*/
			info.rti_info[rt_addrinfo::RTAX_DST] = dst;
			info.rt_missmsg(msgtype, 0, err);
		}
	}
	inet_t::splx();
	return (newrt);
#endif
}

L3_impl::rtentry::~rtentry()
{
	/*register struct ifaddr *ifa;*/
	rt_refcnt--;
	if (rt_refcnt <= 0 && (rt_flags & RTF_UP) == 0)
		if (rt_nodes->rn_flags & (L3_impl::radix_node::RNF_ACTIVE | L3_impl::radix_node::RNF_ROOT))
			//Throw std::runtime_error("rtfree 2");  // remove
		//else if (rt_refcnt < 0)
			return;

}

void L3_impl::rtentry::RTFREE()
{
	if (rt_refcnt <= 1)
		delete this;
	else
		rt_refcnt--;
}

/************************************************************************/
/*                         L3_impl::route	                                */
/************************************************************************/

L3_impl::route::route(inet_os* inet) { ro_rt = new L3_impl::rtentry(&ro_dst, 1, inet); }

void L3_impl::route::rtalloc(inet_os* inet)
{
	if (ro_rt && ro_rt->rt_ifp && (ro_rt->rt_flags & L3_impl::rtentry::RTF_UP))
		return;				 /* XXX */
	ro_rt = new L3_impl::rtentry(&ro_dst, 1, inet);
}

/************************************************************************/
/*                         L3_impl::iphdr		                            */
/************************************************************************/

std::ostream& operator<<(std::ostream& out, const L3_impl::iphdr& ip)
{
	std::ios::fmtflags f(out.flags());
	out << "< IP (" << static_cast<uint32_t>(ip.ip_hl() << 2) <<
		" bytes) :: Version = 0x" << std::hex << static_cast<USHORT>(ip.ip_v()) <<
		" , HeaderLength = 0x" << static_cast<USHORT>(ip.ip_hl()) <<
		" , DiffServicesCP = 0x" << std::setfill('0') << std::setw(2) << ((static_cast<uint8_t>(ip.ip_tos) >> 2) << 2) <<
		" , ExpCongestionNot = 0x" << (static_cast<uint8_t>(ip.ip_tos) << 6) <<
		" , TotalLength = " << std::dec << static_cast<uint16_t>(ip.ip_len) <<
		" , Identification = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(ip.ip_id) <<
		" , FragmentOffset = " << std::dec << ip.ip_off <<
		" , TTL = " << static_cast<uint16_t>(ip.ip_ttl) <<
		" , Protocol = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(ip.ip_p) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(ip.ip_sum) <<
		" , SourceIP = " << inet_ntoa(ip.ip_src);
	out << " , DestinationIP = " << inet_ntoa(ip.ip_dst) <<
		" , >";
	out.flags(f);
	return out;
}

const u_char L3_impl::iphdr::ip_v() const { return ip_v_hl.hb; }
const u_char L3_impl::iphdr::ip_hl() const { return ip_v_hl.lb; }
void L3_impl::iphdr::ip_v(const u_char& ip_v) { ip_v_hl.hb = ip_v; }
void L3_impl::iphdr::ip_hl(const u_char& ip_hl) { ip_v_hl.lb = ip_hl; }

/************************************************************************/
/*                         L3_impl				                        */
/************************************************************************/

void L3_impl::ip_insertoptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, std::shared_ptr<std::vector<byte>>& opt, int& phlen)
{
	struct iphdr* ip(reinterpret_cast<struct iphdr*>(&m->data()[it - m->begin()]));
	struct ipoption* p(reinterpret_cast<struct ipoption*>(&opt->data()[0]));
	unsigned optlen(opt->size() - sizeof(p->ipopt_dst));
	if (optlen + static_cast<u_short>(ip->ip_len) > IP_MAXPACKET)
		/*!
			\bug \code optlen + static_cast<u_short>(ip->ip_len) > IP_MAXPACKET  \endcode should fail
		*/
		return;
	if (p->ipopt_dst.s_addr)
		ip->ip_dst = p->ipopt_dst;

	m->resize(m->size() + optlen);
	std::move_backward(it += sizeof(struct iphdr*), m->end(), m->end());
	std::copy(p->ipopt_list, p->ipopt_list + optlen, it);
	phlen = sizeof(struct iphdr) + optlen;
	ip->ip_len += optlen;
	return;
}
void L3_impl::ip_stripoptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it)
{
	struct L3_impl::iphdr* ip(reinterpret_cast<struct L3_impl::iphdr*>(&m->data()[it - m->begin()]));
	int olen((ip->ip_hl() << 2) - sizeof(struct L3_impl::iphdr));
	std::move(it + olen, m->end(), it);
	m->resize(m->size() - olen);
	ip->ip_hl(sizeof(struct L3_impl::iphdr) >> 2);
}
