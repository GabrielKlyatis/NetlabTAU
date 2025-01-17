/*!
	\file	L3_impl.cpp

	\author	Tom Mahler, contact at tommahler@gmail.com

	\brief	Implements the L3 class.
*/



#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "L3_impl.h"

#include <iomanip>
#include <algorithm>
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

L3_impl::L3_impl(class inet_os& inet, const short& pr_type, const short& pr_protocol, const short& pr_flags)
	: L3(inet, pr_type, pr_protocol, pr_flags) { }

int L3_impl::pr_output(const struct pr_output_args& args) { return ip_output(*reinterpret_cast<const struct ip_output_args*>(&args)); };

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

void L3_impl::print(struct iphdr& ip, uint16_t checksum, std::ostream& str)
{
	std::swap(checksum, ip.ip_sum);
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << "[#] IP packet received!" << std::endl << ip << std::endl;
	std::swap(checksum, ip.ip_sum);
}

void L3_impl::ip_init()
{
	/*
	*	pffindproto returns a pointer to the raw protocol (inetsw[3], Figure 7.14).
	*	Net/3 panics if the raw protocol cannot be located, since it is a required part of the kernel.
	*	If it is missing, the kernel has been mis configured. IP delivers packets that arrive
	*	for an unknown transport protocol to this protocol where they may be handled by a
	*	process outside the kernel.
	*/
	class protosw** pr = inet.pffindproto(AF_INET, IPPROTO_RAW, SOCK_RAW);
	if (pr == nullptr)
		throw std::runtime_error("ip_init");

	/*
	*	The next two loops initialize the ip_protox array. The first loop sets each entry in
	*	the array to pr, the index of the default protocol (3 from Figure 7.22). The second loop
	*	examines each protocol in inetsw (other than the entries with protocol numbers of 0 or
	*	IPPROTO_RAW) and sets the matching entry in ip_protox to refer to the appropriate
	*	inetsw entry. Therefore, pr_protocol in each protosw structure must be the protocol
	*	number expected. to appear in the incoming datagram.
	*/
	const u_char protocol((*pr)->to_swproto());
	for (int i(0); i < IPPROTO_MAX; i++)
		ip_protox[i] = protocol;
	for (pr = reinterpret_cast<class protosw**>(inet.inetdomain()->dom_protosw); pr < inet.inetdomain()->dom_protoswNPROTOSW; pr++)
		if ((*pr) && (*pr)->dom_family() == AF_INET && (*pr)->pr_protocol() && (*pr)->pr_protocol() != IPPROTO_RAW)
			ip_protox[(*pr)->pr_protocol()] = (*pr)->to_swproto();

	/*
	*	ip_init initializes the IP reassembly queue, ipq (Section 10.6), seeds ip_id from
	*	the system clock, and sets the maximum size of the IP input queue (ipintrq) to SO
	*	(ipqmaxlen). ip_id is set from the system clock to provide a random starting point
	*	for datagram identifiers (Section 10.6). Finally, ip_ini t allocates a two-dimensional
	*	array, ip_ifmatrix, to count packets routed between the interfaces in the system.
	*		Remark:	There are many variables within Net/3 that may be modified by a system administrator. To
	*				allow these variables to be changed at run time and without recompiling the kernel, the
	*				default value represented by a constant (IF(LMAXLEN in this case) is assigned to a variable
	*				ipqmaxlen) at compile time. A system administrator can use a kernel debugger such as adb
	*				to change ipqmaxlen and reboot the kernel with the new value. If Figure 7.23 used
	*				IFQ_MAXLEN directly, it would require a recompile of the kernel to change the limit.
	*/
	ipq_t.next = ipq_t.prev = &ipq_t;
	ip_id = static_cast<u_short>(GetTickCount64()) & 0xffff;
}

int L3_impl::done(struct route* ro, struct route& iproute, const int& flags, const int error)
{
	if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt)
		ro->ro_rt->RTFREE();
	return (error);
}

int L3_impl::ip_dooptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it)
{
#ifndef NETLAB_L3_OPTIONS
	return 0;
#else
	struct ip_timestamp* ipt;
	struct in_ifaddr* ia;
	int off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr* sin;
	n_time ntime;

	struct iphdr& ip(*reinterpret_cast<struct iphdr*>(&m->data()[it - m->begin()]));
	struct in_addr dst(ip.ip_dst);
	u_char* cp = reinterpret_cast<u_char*>(&ip + 1);
	int cnt((ip.ip_hl() << 2) - sizeof(struct iphdr)), optlen, opt;
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		if ((opt = cp[IPOPT_OPTVAL]) == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else if ((optlen = cp[IPOPT_OLEN]) <= 0 || optlen > cnt) {
			code = &cp[IPOPT_OLEN] - reinterpret_cast<u_char*>(&ip);
			goto bad;
		}

		switch (opt) {

		default:
			break;

			/*
			* Source routing with record.
			* Find interface with current destination address.
			* If none on this machine then drop if strictly routed,
			* or do nothing if loosely routed.
			* Record interface address and bring up next address
			* component.  If strictly routed make sure next
			* address is on directly accessible net.
			*/
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char*)&ip;
				goto bad;
			}
			ipaddr.sin_addr = ip.ip_dst;
			ia = (struct in_ifaddr*)
				ifa_ifwithaddr((struct sockaddr*)&ipaddr);
			if (ia == 0) {
				if (opt == IPOPT_SSRR) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				}
				/*
				* Loose routing, and not at next destination
				* yet; nothing to do except forward.
				*/
				break;
			}
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr)) {
				/*
				* End of source route.  Should be for us.
				*/
				save_rte(cp, ip.ip_src);
				break;
			}
			/*
			* locate outgoing interface
			*/
			bcopy((caddr_t)(cp + off), (caddr_t)&ipaddr.sin_addr,
				sizeof(ipaddr.sin_addr));
			if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
#define	SA	struct sockaddr *
				if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0)
					ia = (INA)ifa_ifwithnet((SA)&ipaddr);
			}
			else
				ia = ip_rtaddr(ipaddr.sin_addr);
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			bcopy((caddr_t) & (IA_SIN(ia)->sin_addr),
				(caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			/*
			* Let ip_intr's mcast routing check handle mcast pkts
			*/
			forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
			break;

		case IPOPT_RR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char*)ip;
				goto bad;
			}
			/*
			* If no space remains, ignore.
			*/
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr))
				break;
			bcopy((caddr_t)(&ip->ip_dst), (caddr_t)&ipaddr.sin_addr,
				sizeof(ipaddr.sin_addr));
			/*
			* locate outgoing interface; if we're the destination,
			* use the incoming interface (should be same).
			*/
			if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0 &&
				(ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_HOST;
				goto bad;
			}
			bcopy((caddr_t) & (IA_SIN(ia)->sin_addr),
				(caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char*)ip;
			ipt = (struct ip_timestamp*)cp;
			if (ipt->ipt_len < 5)
				goto bad;
			if (ipt->ipt_ptr > ipt->ipt_len - sizeof(long)) {
				if (++ipt->ipt_oflw == 0)
					goto bad;
				break;
			}
			sin = (struct in_addr*)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr + sizeof(n_time) +
					sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr((SA)&ipaddr,
					m->m_pkthdr.rcvif);
				if (ia == 0)
					continue;
				bcopy((caddr_t)&IA_SIN(ia)->sin_addr,
					(caddr_t)sin, sizeof(struct in_addr));
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr + sizeof(n_time) +
					sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				bcopy((caddr_t)sin, (caddr_t)&ipaddr.sin_addr,
					sizeof(struct in_addr));
				if (ifa_ifwithaddr((SA)&ipaddr) == 0)
					continue;
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				goto bad;
			}
			ntime = iptime();
			bcopy((caddr_t)&ntime, (caddr_t)cp + ipt->ipt_ptr - 1,
				sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward) {
		ip_forward(m, 1);
		return (1);
	}
	return (0);
bad:
	ip->ip_len -= ip->ip_hl << 2;   /* XXX icmp_error adds in hdr length */
	icmp_error(m, type, code, 0, 0);
	ipstat.ips_badoptions++;
	return (1);
#endif
}

void L3_impl::ip_forward(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, const int& srcrt)
{
#ifdef NETLAB_L3_FORWARDING
	register struct ip* ip = mtod(m, struct ip*);
	register struct sockaddr_in* sin;
	register struct rtentry* rt;
	int error, type = 0, code;
	struct mbuf* mcopy;
	n_long dest;
	struct ifnet* destifp;

	dest = 0;
	if (m->m_flags & M_BCAST || in_canforward(ip->ip_dst) == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
		return;
	}
	HTONS(ip->ip_id);
	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return;
	}
	ip->ip_ttl -= IPTTLDEC;

	sin = (struct sockaddr_in*)&ipforward_rt.ro_dst;
	if ((rt = ipforward_rt.ro_rt) == 0 ||
		ip->ip_dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = ip->ip_dst;

		rtalloc(&ipforward_rt);
		if (ipforward_rt.ro_rt == 0) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, dest, 0);
			return;
		}
		rt = ipforward_rt.ro_rt;
	}

	/*
	* Save at most 64 bytes of the packet in case
	* we need to generate an ICMP message to the src.
	*/
	mcopy = m_copy(m, 0, imin((int)ip->ip_len, 64));

#ifdef GATEWAY
	ip_ifmatrix[rt->rt_ifp->if_index +
		if_index * m->m_pkthdr.rcvif->if_index]++;
#endif
	/*
	* If forwarding packet using same interface that it came in on,
	* perhaps should send a redirect to sender to shortcut a hop.
	* Only send redirect if source is sending directly to us,
	* and if packet was not source routed (or has any options).
	* Also, don't send redirect if forwarding using a default route
	* or a route modified by a redirect.
	*/
#define	satosin(sa)	((struct sockaddr_in *)(sa))
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
		(rt->rt_flags & (RTF_DYNAMIC | RTF_MODIFIED)) == 0 &&
		satosin(rt_key(rt))->sin_addr.s_addr != 0 &&
		ipsendredirects && !srcrt) {
#define	RTA(rt)	((struct in_ifaddr *)(rt->rt_ifa))
		u_long src = ntohl(ip->ip_src.s_addr);

		if (RTA(rt) &&
			(src & RTA(rt)->ia_subnetmask) == RTA(rt)->ia_subnet) {
			if (rt->rt_flags & RTF_GATEWAY)
				dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
			else
				dest = ip->ip_dst.s_addr;
			/* Router requirements says to only send host redirects */
			type = ICMP_REDIRECT;
			code = ICMP_REDIRECT_HOST;
		}
	}

	error = ip_output(m, (struct mbuf*)0, &ipforward_rt, IP_FORWARDING
#ifdef DIRECTED_BROADCAST
		| IP_ALLOWBROADCAST
#endif
		, 0);
	if (error)
		ipstat.ips_cantforward++;
	else {
		ipstat.ips_forward++;
		if (type)
			ipstat.ips_redirectsent++;
		else {
			if (mcopy)
				m_freem(mcopy);
			return;
		}
	}
	if (mcopy == NULL)
		return;
	destifp = NULL;

	switch (error) {

	case 0:				/* forwarded, but need redirect */
		/* type, code set above */
		break;

	case ENETUNREACH:		/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		break;

	case EMSGSIZE:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_NEEDFRAG;
		if (ipforward_rt.ro_rt)
			destifp = ipforward_rt.ro_rt->rt_ifp;
		ipstat.ips_cantfrag++;
		break;

	case ENOBUFS:
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;
	}
	icmp_error(mcopy, type, code, dest, destifp);
#endif
}

void L3_impl::ours(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, struct iphdr& ip, int& hlen)
{

	/*
	*	Recall that ip_off contains the DF bit, the MF bit, and the fragment offset. The DF
	*	bit is masked out and if either the MF bit or fragment offset is nonzero, the packet is a
	*	fragment that must be reassembled. If both are zero, the packet is a complete datagram,
	*	the reassembly code is skipped and the else clause at the end of Figure 10.11 is executed,
	*	which excludes the header length from the total datagram length.
	*
	* If offset or IP_MF are set, must reassemble.
	* Otherwise, nothing need be done.
	* (We could look in the reassembly queue to see
	* if the packet was previously fragmented,
	* but it's not worth the time; just let them time out.)
	*/

	// check if dont fragment bit is on

	if (!((ip.ip_off & iphdr::IP_DF) == iphdr::IP_DF)) {

		/*
		*	Net/3 keeps incomplete datagrams on the global doubly linked list, ipq. The name
		*	is somewhat confusing since the data structure isn't a queue. That is, insertions and
		*	deletions can occur anywhere in the list, not just at the ends. We'll use the term list to
		*	emphasize this fact.
		*		ours performs a linear search of the list to locate the appropriate datagram for
		*	the current fragment. Remember that fragments are uniquely identified by the 4-tuple:
		*	{ip_id, ip_src, ip_dst, ip_p}. Each entry in ipq is a list of fragments and fp points
		*	to the appropriate list if ours finds a match.
		*		Remark:	Net/3 uses linear searches to access many of its data structures. While simple,
		*		this method can	become a bottleneck in hosts supporting large numbers of network connections.
		*
		* Look for queue of fragments
		* of this datagram.
		*/
		struct ipq* fp;

		bool found(false);
		for (fp = ipq_t.next; fp != &ipq_t; fp = fp->next)
		{
			if (fp == nullptr)
			{
				break;
			}

			if (ip.ip_id == fp->ipq_id &&
				ip.ip_src.s_addr == fp->ipq_src.s_addr &&
				ip.ip_dst.s_addr == fp->ipq_dst.s_addr &&
				ip.ip_p == fp->ipq_p)
			{
				found = true;
				break;
			}
		}

		if (found)
		{
			ip_fragment* pointer = fp->fragments;
			while (pointer->next_fragment != nullptr)
			{
				pointer = pointer->next_fragment;
			}
			fp->total_length += ip.ip_len - sizeof(iphdr);
			pointer->next_fragment = new ip_fragment(m);
		}
		else
		{
			fp = new struct ipq(); // need to free memory
			fp->ipq_id = ip.ip_id;
			fp->ipq_src.s_addr = ip.ip_src.s_addr;
			fp->ipq_dst.s_addr = ip.ip_dst.s_addr;
			fp->ipq_p = ip.ip_p;
			fp->total_length = ip.ip_len - sizeof(iphdr);
			fp->fragments = new ip_fragment(m);

			ipq* last_ipq = &ipq_t;
			last_ipq->next = fp;

		}


		/*
		*	At found, the packet is modified by ours to facilitate reassembly:
		*		a.	ours changes ip_len to exclude the standard IP header and any options.
		*			We must keep this in mind to avoid confusion with the standard interpretation
		*			of ip_len, which includes the standard header, options, and data. ip_len is
		*			also changed if the reassembly code is skipped because this is not a fragment.
		*
		* Adjust ip_len to not reflect header,
		* set ip_mff if more fragments are expected,
		* convert offset of this to bytes.
		*/
		ip.ip_len -= hlen;

		/*
		*	ours copies the MF flag into the low-order bit of ipf_mff, which overlays
		*	ip_tos (&= ~1 clears the low-order bit only). Notice that ip must be cast to a
		*	pointer to an ipasfrag structure before ipf_mff is a valid member. Section
		*	10.6 and Figure 10.14 describe the ipasfrag structure.
		*		Remark:	Although RFC 1122 requires the IP layer to provide a mechanism that enables the transport
		*				layer to set ip_tos for every outgoing datagram, it only recommends that the IP layer pass
		*				ip_tos values to the transport layer at the destination host. Since the low-order bit of the
		*				TOS field must always be 0, it is availabJe to hold the MF bit while ip_of f (where the MF bit
		*				is normally found) is used by the reassembly algorithm.
		*	ip_off can now be accessed as a 16-bit offset instead of 3 flag bits and a 13-bit
		*	offset.
		*/
		reinterpret_cast<struct ipasfrag*>(&ip)->ipf_mff &= ~1;
		if (ip.ip_off & iphdr::IP_MF)
			reinterpret_cast<struct ipasfrag*>(&ip)->ipf_mff |= 1;


		/*
		*	ipf_mff and ip_off determine if ours should attempt reassembly. Figure
		*	10.12 describes the different cases and the corresponding actions. Remember that
		*	fp points to the list of fragments the system has previously received for the datagram.
		*	Most of the work is done by ip_reass.
		*	If ip_reass is able to assemble a complete datagram by combining the current
		*	fragment with previously received fragments, it returns a pointer to the reassembled
		*	datagram. If reassembly is not possible, ip_reass saves the fragment and ours
		*	jumps to next to process the next packet (Figure 8.12).
		*
		* If datagram marked as having more fragments
		* or if this is not the first fragment,
		* attempt reassembly; if it succeeds, proceed. ???????
		*
		* if no more frags try to reasmble
		*/
		if (((ip.ip_off & iphdr::IP_MF) == 0) && ip.ip_p == 0x11) // for now support only in udp
		{
			// attempt to reasmble
			ip_fragment* pointer = fp->fragments;
			size_t ethr_ip_header_size = sizeof(struct L2::ether_header) + sizeof(struct L3_impl::iphdr);

			// create the reasmble buffer & iterator
			std::shared_ptr<std::vector<byte>> m_reasemble_packet(new std::vector<byte>(ethr_ip_header_size + fp->total_length));
			std::vector<byte>::iterator it_reasemble(m_reasemble_packet->begin());

			// copy ethernet and ip header 
			memcpy(&(*it_reasemble), &(*pointer->frag_data->begin()), ethr_ip_header_size);
			struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(&(*(it_reasemble + sizeof(struct L2::ether_header)))); // point to start of iphdr
			ip_header->ip_len = sizeof(struct L3_impl::iphdr) + fp->total_length; // reasmble ip length

			while (pointer != nullptr)
			{
				// fragment iterator
				std::vector<byte>::iterator it_fragment(pointer->frag_data->begin());
				struct iphdr* fragment_ip_header(reinterpret_cast<struct iphdr*>(&(*(it_fragment + sizeof(struct L2::ether_header)))));

				// copy fragment data section
				uint16_t fragment_offset = fragment_ip_header->ip_off << 3; // multiply by 8
				uint16_t fragment_length = fragment_ip_header->ip_len;
				if (fragment_offset + fragment_length > fp->total_length) // detect missing frags
				{
					return; // maybe need to free the entry?
				}
				memcpy(&(*(it_reasemble + ethr_ip_header_size + fragment_offset)), &(*(it_fragment + ethr_ip_header_size)), fragment_length);

				// next fragment and free memory
				ip_fragment* tmp = pointer;
				pointer = pointer->next_fragment;
				delete tmp;
			}

			// assign new packet
			//m = m_reasemble_packet;
			return inet.inetsw(static_cast<protosw::SWPROTO_>(ip_protox[ip.ip_p]))->pr_input(protosw::pr_input_args(m_reasemble_packet, it_reasemble + sizeof(struct L2::ether_header), hlen));
		}
		return;
	}
	else
		ip.ip_len -= hlen;

	/*
	*	Transport demultiplexing:
	*	The protocol specified in the datagram (ip_p) is mapped with the ip_protox
	*	array (Figure 7.22) to an index into the inetsw array. ours calls the pr_input
	*	function from the selected protosw structure to process the transport message contained
	*	within the datagram. When pr_input returns, ours proceeds with the next
	*	packet on oursq.
	*	It is important to notice that transport-level processing for each packet occurs
	*	within the processing loop of ours. There is no queuing of incoming packets
	*	between IP and the transport protocols, unlike the queuing in SVR4 streams implementations
	*	of TCP/IP.
	* Switch out to protocol's input routine.
	*/
	return inet.inetsw(static_cast<protosw::SWPROTO_>(ip_protox[ip.ip_p]))->pr_input(protosw::pr_input_args(m, it, hlen));
}