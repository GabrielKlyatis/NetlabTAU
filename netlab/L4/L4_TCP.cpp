#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#ifndef WINSOCK2
#define WINSOCK2
#include <WinSock2.h>
#endif

#include <algorithm>
#include <sstream>
#include <iostream>
#include <Shlobj.h>
#include <random>
#include <algorithm>

#ifdef IN
#undef IN
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include "../L1/NIC.h"
#include "../L4/L4_TCP.h"
#include "../L2/L2.h"
#include "../L5/L5.h"

#include <iomanip>


#include <boost/range.hpp>

#define FIXBUG_959

/************************************************************************/
/*                         TCP Control Block							*/
/************************************************************************/

void tcpcb::log_snd_cwnd(u_long snd_cwnd) {

	log.update(snd_cwnd);
}

int tcpcb::tcpcb_logger::log_number(0);

tcpcb::tcpcb_logger::tcpcb_logger()
	: log(std::ofstream(std::string("log/connection_") + std::to_string(log_number++) + std::string(".txt"), std::ios_base::out | std::ios_base::trunc)),
	start(std::chrono::high_resolution_clock::now())
{

}

void tcpcb::tcpcb_logger::update(u_long snd_cwnd)
{
	log << std::chrono::duration_cast<seconds>(std::chrono::high_resolution_clock::now() - start).count()
		<< "\t" << std::to_string(snd_cwnd) << std::endl;
}

inline bool tcpcb::TCPS_HAVERCVDSYN() const { return t_state >= TCPS_SYN_RECEIVED; }

inline bool tcpcb::TCPS_HAVERCVDFIN() const { return t_state >= TCPS_TIME_WAIT; }

inline const u_char tcpcb::tcp_outflags() const
{
	switch (t_state) {
	case TCPS_CLOSED:
		return static_cast<u_char>(tcphdr::TH_RST | tcphdr::TH_ACK);
		break;
	case TCPS_LISTEN:
		return 0;
		break;
	case TCPS_SYN_SENT:
		return static_cast<u_char>(tcphdr::TH_SYN);
		break;
	case TCPS_SYN_RECEIVED:
		return static_cast<u_char>(tcphdr::TH_SYN | tcphdr::TH_ACK);
		break;
	case TCPS_ESTABLISHED:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_CLOSE_WAIT:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_FIN_WAIT_1:
		return static_cast<u_char>(tcphdr::TH_FIN | tcphdr::TH_ACK);
		break;
	case TCPS_CLOSING:
		return static_cast<u_char>(tcphdr::TH_FIN | tcphdr::TH_ACK);
		break;
	case TCPS_LAST_ACK:
		return static_cast<u_char>(tcphdr::TH_FIN | tcphdr::TH_ACK);
		break;
	case TCPS_FIN_WAIT_2:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_TIME_WAIT:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	default:
		break;
	}
	throw std::runtime_error("tcp_outflags: No such state!");
}

inline class tcpcb* tcpcb::intotcpcb(class inpcb_impl* ip) { return dynamic_cast<class tcpcb*>(ip); }

inline class tcpcb* tcpcb::intotcpcb(class inpcb* ip) { return dynamic_cast<class tcpcb*>(ip); }

inline class tcpcb* tcpcb::sototcpcb(socket* so) { return dynamic_cast<class tcpcb*>(so->so_pcb); }

template<typename T>
inline bool tcpcb::SEQ_LT(T a, T b) { return static_cast<int>(a - b) < 0; }

template<typename T>
inline bool tcpcb::SEQ_LEQ(T a, T b) { return static_cast<int>(a - b) <= 0; }

template<typename T>
static inline bool tcpcb::SEQ_GT(T a, T b) { return static_cast<int>(a - b) > 0; }

template<typename T>
static inline bool tcpcb::SEQ_GEQ(T a, T b) { return static_cast<int>(a - b) >= 0; }

class tcpcb* tcpcb::in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags)
{
	return dynamic_cast<class tcpcb*>(inpcb_impl::in_pcblookup(faddr, fport_arg, laddr, lport_arg, flags));
}

void tcpcb::tcp_template()
{
	if (t_template == nullptr)
		t_template = new tcpiphdr();
	t_template->tcp_template(t_inpcb->inp_faddr(), t_inpcb->inp_fport(), t_inpcb->inp_laddr(), t_inpcb->inp_lport());
}

inline void tcpcb::tcp_rcvseqinit() { rcv_adv = rcv_nxt = irs + 1; }

inline void tcpcb::tcp_sendseqinit() { snd_una = snd_nxt = snd_max = snd_up = iss; }

inline void tcpcb::tcp_quench() { log_snd_cwnd(snd_cwnd = t_maxseg); }

inline short tcpcb::TCP_REXMTVAL() const
{
	return (t_srtt >> L4_TCP::TCP_RTT_SHIFT) + t_rttvar;
}

void tcpcb::tcp_xmit_timer(short rtt)
{
	if (t_srtt != 0) {
		/*
		* srtt is stored as fixed point with 3 bits after the
		* binary point (i.e., scaled by 8).  The following magic
		* is equivalent to the smoothing algorithm in rfc793 with
		* an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		* point).  Adjust rtt to origin 0.
		*/
		short delta(rtt - 1 - (t_srtt >> L4_TCP::TCP_RTT_SHIFT));
		if ((t_srtt += delta) <= 0)
			t_srtt = 1;
		/*
		* We accumulate a smoothed rtt variance (actually, a
		* smoothed mean difference), then set the retransmit
		* timer to smoothed rtt + 4 times the smoothed variance.
		* rttvar is stored as fixed point with 2 bits after the
		* binary point (scaled by 4).  The following is
		* equivalent to rfc793 smoothing with an alpha of .75
		* (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		* rfc793's wired-in beta.
		*/
		if (delta < 0)
			delta = -delta;
		if ((t_rttvar += (delta -= (t_rttvar >> L4_TCP::TCP_RTTVAR_SHIFT))) <= 0)
			t_rttvar = 1;
	}
	else {
		/*
		* No rtt measurement yet - use the unsmoothed rtt.
		* Set the variance to half the rtt (so our first
		* retransmit happens at 3*rtt).
		*/
		t_srtt = rtt << L4_TCP::TCP_RTT_SHIFT;
		t_rttvar = rtt << (L4_TCP::TCP_RTTVAR_SHIFT - 1);
	}
	t_rtt = t_rxtshift = 0;

	/*
	* the retransmit should happen at rtt + 4 * rttvar.
	* Because of the way we do the smoothing, srtt and rttvar
	* will each average +1/2 tick of bias.  When we compute
	* the retransmit timer, we want 1/2 tick of rounding and
	* 1 extra tick because of +-1/2 tick uncertainty in the
	* firing of the timer.  The bias will give us exactly the
	* 1.5 tick we need.  But, because the bias is
	* statistical, we have to test that we don't drop below
	* the minimum feasible timer (which is 2 ticks).
	*/
	L4_TCP::TCPT_RANGESET(t_rxtcur, TCP_REXMTVAL(), t_rttmin, L4_TCP::TCPTV_REXMTMAX);

	/*
	* We received an ack for a packet that wasn't retransmitted;
	* it is probably safe to discard any error indications we've
	* received recently.  This isn't quite right, but close enough
	* for now (a route might have failed after we sent a segment,
	* and the return path might not be symmetrical).
	*/
	t_softerror = 0;
}

void tcpcb::tcp_canceltimers() {
	for (int i = 0; i < TCPT_NTIMERS; i++)
		t_timer[i] = 0;
}

/************************************************************************/
/*								tcphdr									*/
/************************************************************************/

std::ostream& operator<<(std::ostream& out, const tcphdr& tcp) {
	std::ios::fmtflags f(out.flags());
	out << "< TCP (" << static_cast<uint32_t>(tcp.th_off() << 2) <<
		" bytes) :: SourcePort = " << std::dec << ntohs(static_cast<uint16_t>(tcp.th_sport)) <<
		" , DestinationPort = " << std::dec << ntohs(static_cast<uint16_t>(tcp.th_dport)) <<
		" , Seq # = " << std::dec << static_cast<uint32_t>(tcp.th_seq) <<
		" , ACK # = " << std::dec << static_cast<uint32_t>(tcp.th_ack) <<
		" , HeaderLength = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(tcp.th_off()) <<
		" , Flags = 0x" << std::setfill('0') << std::setw(3) << std::hex << static_cast<uint16_t>(tcp.th_flags) <<
		" (";
	if (tcp.th_flags & tcp.TH_URG)
		out << "URG, ";
	if (tcp.th_flags & tcp.TH_ACK)
		out << "ACK, ";
	if (tcp.th_flags & tcp.TH_PUSH)
		out << "PUSH, ";
	if (tcp.th_flags & tcp.TH_RST)
		out << "RST, ";
	if (tcp.th_flags & tcp.TH_SYN)
		out << "SYN, ";
	if (tcp.th_flags & tcp.TH_FIN)
		out << "FIN, ";
	out << ")" <<
		" , WinSize = " << std::dec << static_cast<uint16_t>(tcp.th_win) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(tcp.th_sum) <<
		" , UrgentPointer = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(tcp.th_urp) <<
		" , >";
	out.flags(f);
	return out;
}

/************************************************************************/
/*								tcpiphdr								*/
/************************************************************************/

tcpiphdr::tcpiphdr() : ti_i(ipovly()), ti_t(tcphdr()) { }

tcpiphdr::tcpiphdr(byte* m, const u_char& ih_pr, const short& ip_len, const in_addr& ip_src, const in_addr& ip_dst)
	: ti_i(ih_pr, ip_len, ip_src, ip_dst), ti_t(*reinterpret_cast<struct tcphdr*>(m)) {	}

std::ostream& operator<<(std::ostream& out, const struct tcpiphdr& ti)
{
	return out << ti.ti_i << ti.ti_t;
}

void tcpiphdr::tcp_template(const struct in_addr& inp_faddr, const u_short& inp_fport, const struct in_addr& inp_laddr, const u_short& inp_lport)
{
	ti_seq() = ti_ack() = ti_ack() = 0;
	ti_flags() = 0;
	ti_win() = ti_sum() = ti_urp() = 0;
	ti_x2(0);
	ti_off(5);
	ti_sport() = inp_lport;
	ti_dport() = inp_fport;
	ti_next(0);
	ti_prev(0);
	ti_x1() = 0;
	ti_pr() = IPPROTO_TCP;
	ti_len() = htons(sizeof(struct tcpiphdr) - sizeof(struct L3::iphdr));
	ti_src() = inp_laddr;
	ti_dst() = inp_faddr;
}

inline std::shared_ptr<std::vector<byte>> tcpiphdr::REASS_MBUF() { return *reinterpret_cast<std::shared_ptr<std::vector<byte>>*>(&ti_t); }

inline void tcpiphdr::insque(struct tcpiphdr& head)
{
	ti_next(head.ti_next());
	head.ti_next(this);
	ti_prev(&head);
	if (ti_next())
		ti_next()->ti_prev(this);
}

inline void tcpiphdr::remque()
{
	if (ti_next())
		ti_next()->ti_prev(ti_prev());
	if (ti_prev()) {
		ti_prev()->ti_next(ti_next());
		ti_prev(nullptr);
	}
}

/************************************************************************/
/*								tcpiphdr::ipovly						*/
/************************************************************************/

tcpiphdr::ipovly::ipovly()
	: ih_pr(0), ih_len(0), ih_src(struct in_addr()), ih_dst(struct in_addr()), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

tcpiphdr::ipovly::ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst)
	: ih_pr(ih_pr), ih_len(ih_len), ih_src(ih_src), ih_dst(ih_dst), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

std::ostream& operator<<(std::ostream& out, const struct tcpiphdr::ipovly& ip) {
	std::ios::fmtflags f(out.flags());
	out << "< Pseudo IP (" << static_cast<uint32_t>(sizeof(struct tcpiphdr::ipovly)) <<
		" bytes) :: Unsused = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_x1) <<
		" , Protocol = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_pr) <<
		" , Protocol Length = " << std::dec << htons(static_cast<uint16_t>(ip.ih_len)) <<
		" , SourceIP = " << inet_ntoa(ip.ih_src);
	out << " , DestinationIP = " << inet_ntoa(ip.ih_dst) <<
		" , >";
	out.flags(f);
	return out;
}

/***************************************************************************************/
/*							L4_TCP - Interface & Implementation						   */
/***************************************************************************************/


void L4_TCP::pr_init()
{
	tcp_saveti = nullptr;
	tcp_last_inpcb = nullptr;
	tcb.inp_next = tcb.inp_prev = &tcb;
	tcp_last_inpcb = dynamic_cast<class inpcb_impl*>(&tcb);
	std::random_device rd;
	tcp_iss = rd();	/* An improvement, may be wrong, but better than a constant */

	tcp_sendspace = TCP_MAXWIN;
	tcp_recvspace = TCP_MAXWIN;
}

void L4_TCP::pr_fasttimo()
{
	std::lock_guard<std::mutex> lock(inet._splnet);

	class inpcb_impl* inp(dynamic_cast<class inpcb_impl*>(tcb.inp_next));
	if (inp) {
		class tcpcb* tp;
		for (; inp != &tcb; inp = dynamic_cast<class inpcb_impl*>(inp->inp_next))
			if ((tp = dynamic_cast<class tcpcb*>(inp->inp_ppcb)) && (tp->t_flags & tcpcb::TF_DELACK)) {
				tp->t_flags &= ~tcpcb::TF_DELACK;
				tp->t_flags |= tcpcb::TF_ACKNOW;
				(void)tcp_output(*tp);
			}
	}
}

void L4_TCP::pr_slowtimo()
{
	std::lock_guard<std::mutex> lock(inet._splnet);

	/*
	*	tcp_rnaxidle is initialized to 10 minutes. This is the maximum amount of time
	*	TCP will send keepalive probes to another host, waiting for a response from that host.
	*	This variable is also used with the FIN_WAIT_2 timer, as we describe in Section 25.6.
	*	This initialization statement could be moved to tcp_ini t, since it only needs to be
	*	evaluated when the system is initialized (see Exercise 25.2).
	*/
	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;

	/*
	*	Check each timer counter In all TCP control blocks:
	*		Each Internet PCB on the TCP list that has a corresponding TCP control block is
	*	checked. Each of the four timer counters for each connection is tested, and if nonzero,
	*	the counter is decremented. When the timer reaches 0, a PRU_SLOWTIMO request is
	*	issued. We'll see that this request calls the function tcp_tirners, which we describe
	*	later in this chapter.
	*		The fourth argument to tcp_usrreq is a pointer to an mbuf. But this argument is
	*	actually used for different purposes when the mbuf pointer is not required. Here we
	*	see the index i is passed, telling the request which timer has expired. The funnylooking
	*	cast of i to an mbuf pointer is to avoid a compile-time error.
	*		Notice that if there are no TCP connections active on the host (tcb. inp_next is
	*	null), neither tcp_iss nor tcp_now is incremented. This would occur only when the
	*	system is being initialized, since it would be rare to find a Unix system attached to a
	*	network without a few TCP servers active.
	*
	* Search through tcb's and update active timers.
	*/
	class inpcb_impl* ip(dynamic_cast<inpcb_impl*>(tcb.inp_next));
	if (ip == nullptr)
		return;
	class inpcb_impl* ipnxt;
	for (; ip != &tcb; ip = ipnxt) {
		ipnxt = dynamic_cast<inpcb_impl*>(ip->inp_next);
		class tcpcb* tp(tcpcb::intotcpcb(ip));
		if (tp == nullptr || tp->t_state == tcpcb::TCPS_LISTEN)
			continue;
		for (size_t i = 0; i < TCPT_NTIMERS; i++)
			if (tp->t_timer[i] && --tp->t_timer[i] == 0) {
				(void)pr_usrreq(dynamic_cast<socket*>(tp->t_inpcb->inp_socket), PRU_SLOWTIMO, std::shared_ptr<std::vector<byte>>(nullptr), reinterpret_cast<struct sockaddr*>(i), sizeof(i), std::shared_ptr<std::vector<byte>>(nullptr));

				/*
				*	Check If TCP control block has been deleted:
				*	Before examining the timers for a control block, a pointer to the next Internet PCB is
				*	saved in ipnxt. Each time the PRU_SLOWTIMO request returns, tcp_slowtirno checks
				*	whether the next PCB in the TCP list still points to the PCB that's being processed. If
				*	not, it means the control block has been deleted-perhaps the 2MSL timer expired or
				*	the retransmission timer expired and TCP is giving up on this connection-causing a
				*	jump to tpgone, skipping the remaining timers for this control block, and moving on to
				*	the next PCB.
				*/
				if (ipnxt->inp_prev != ip)
					goto tpgone;
			}

		/*
		*	Count Idle time:
		*	t_idle is incremented for the control block. This counts the number of 500-ms
		*	clock ticks since the last segment was received on this connection. It is set to 0 by
		*	tcp_input when a segment is received on the connection and used for three purposes:
		*		(1)	by the keepalive algorithm to send a probe after the connection is idle for 2 hours,
		*		(2)	to drop a connection in the FIN_WAIT_2 state that is idle for 10 minutes and 75 seconds, and
		*		(3)	by tcp_output to return to the slow start algorithm after the connection has
		*			been idle for a while.
		*/
		tp->t_idle++;

		/*
		*	Increment RTT counter:
		*	If this connection is timing an outstanding segment, t_rtt is nonzero and counts
		*	the number of 500-ms clock ticks until that segment is acknowledged. It is initialized to
		*	1 by tcp_output when a segment is transmitted whose KIT should be timed.
		*	tcp_slowtimo increments this counter.
		*/
		if (tp->t_rtt)
			tp->t_rtt++;
	tpgone:
		;
	}

	/*
	*	Increment initial send sequence number:
	*	tcp_iss was initialized to 1 by tcp_ini t. Every 500 ms it is incremented by
	*	64,000: 128,000 (TCP ISSINCR) divided by 2 (PR_SLOWHZ). This is a rate of about once
	*	every 8 microseconds, although tcp_iss is incremented only twice a second. We'll see
	*	that tcp_iss is also incremented by 64,000 each time a connection is established, either
	*	actively or passively.
	*		Remark:	RFC 793 specifies that the initial sequence number should increment roughly every 4 microseconds,
	*				or 250,000 times a second. The Net/3 value increments at about one-half this rate.
	*/
	TCP_ISSINCR(PR_SLOWHZ);	/* increment iss */

	/*
	*	Increment RFC 1323 timestamp value:
	*	tcp_now is initialized to 0 on bootstrap and incremented every 500 ms. It is used
	*	by the timestamp option defined in RFC 1323 [Jacobson, Braden, and Borman 1992),
	*	which we describe in Section 26.6.
	*/
	tcp_now++;	/* for timestamps */
}

/************************************************************************/
/*				  L4_TCP_impl pr_usrreq						            */
/************************************************************************/

int L4_TCP::pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
	struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) {
	/*
	*	Control Information Is Invalid
	*	A call to sendmsg specifying control information is invalid for a TCP socket. If this
	*	happens, the mbufs are released and EINVAL is returned.
	*/
	if (control)
		return (EINVAL);

	/*
	*	This remainder of the function executes at splnet. This is overly conservative
	*	locking to avoid sprinkling the individual case statements with calls to splnet when
	*	the calls are really necessary. As we mentioned with Figure 23.15, setting the processor
	*	priority to splnet only stops a software interrupt from causing the IP input routine to
	*	be executed (which could call tcp_input). It does not prevent the interface layer from
	*	accepting incoming packets and placing them onto IP's input queue.
	*	The pointer to the Internet PCB is obtained from the socket structure pointer. The
	*	only time the resulting PCB pointer is allowed to be a null pointer is when the
	*	PRU_ATTACH request is issued, which occurs in response to the socket system call.
	*/
	class inpcb* inp(so->so_pcb);

	/*
	*	If inp is nonnull, the current connection state is saved in ostate for the call to
	*	tcp_trace at the end of the function.
	*
	* When a TCP is attached to a socket, then there will be
	* a (struct inpcb) pointed at by the socket, and this
	* structure will point at a subsidary (struct tcpcb).
	*/
	if (inp == nullptr && req != PRU_ATTACH)
		return (EINVAL);		/* XXX */

	class tcpcb* tp(nullptr);
	int ostate(0);
	/*!
		\bug
		WHAT IF TP IS 0?
	*/
	if (inp && (tp = tcpcb::intotcpcb(inp)))
		ostate = tp->t_state;

	int error(0);
	switch (req) {

		/*
		* TCP attaches to socket via PRU_ATTACH, reserving space,
		* and an internet control block.
		*/
	case PRU_ATTACH:
		if (inp) {
			error = EISCONN;
			break;
		}
		if (error = tcp_attach(*dynamic_cast<socket*>(so)))
			break;
		if ((so->so_options & SO_LINGER) && so->so_linger == 0)
			so->so_linger = TCP_LINGERTIME;
		tp = tcpcb::sototcpcb(dynamic_cast<socket*>(so));
		break;

		/*
		* PRU_DETACH detaches the TCP protocol from the socket.
		* If the protocol state is non-embryonic, then can't
		* do this directly: have to initiate a PRU_DISCONNECT,
		* which may finish later; embryonic TCB's can just
		* be discarded here.
		*/
	case PRU_DETACH:
		if (tp && tp->t_state > tcpcb::TCPS_LISTEN)
			tp = tcp_disconnect(*tp);
		else
			tp = tcp_close(*tp);
		break;

		/*
		* Give the socket an address.
		*/
	case PRU_BIND:
		if (error = inp->in_pcbbind(reinterpret_cast<struct sockaddr_in*>(nam), nam_len))
			break;
		break;

		/*
		* Prepare to accept connections.
		*/
	case PRU_LISTEN:
		if (inp->inp_lport() == 0)
			error = inp->in_pcbbind(nullptr, 0);
		if (error == 0)
			tp->t_state = tcpcb::TCPS_LISTEN;
		break;

		/*
		* Initiate connection to peer.
		* Create a template for use in transmissions on this connection.
		* Enter SYN_SENT state, and mark socket as connecting.
		* Start keep-alive timer, and seed output sequence space.
		* Send initial segment on connection.
		*/
	case PRU_CONNECT:
		if (inp->inp_lport() == 0)
			if (error = inp->in_pcbbind(nullptr, 0))
				break;
		if (error = inp->in_pcbconnect(reinterpret_cast<sockaddr_in*>(const_cast<struct sockaddr*>(nam)), nam_len))
			break;
		tp->tcp_template();
		if (tp->t_template == 0) {
			inp->in_pcbdisconnect();
			error = ENOBUFS;
			break;
		}
		/* Compute window scaling to request.  */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT && static_cast<u_long>(TCP_MAXWIN << tp->request_r_scale) < dynamic_cast<socket*>(so)->so_rcv.capacity())
			tp->request_r_scale++;
		dynamic_cast<socket*>(so)->soisconnecting();
		tp->t_state = tcpcb::TCPS_SYN_SENT;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
		tp->iss = tcp_iss;
		TCP_ISSINCR();
		tp->tcp_sendseqinit();
		error = tcp_output(*tp);
		break;

		/*
		* Create a TCP connection between two sockets.
		*/
	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

		/*
		* Initiate disconnect from peer.
		* If connection never passed embryonic stage, just drop;
		* else if don't need to let data drain, then can just drop anyways,
		* else have to begin TCP shutdown process: mark socket disconnecting,
		* drain unread data, state switch to reflect user close, and
		* send segment (e.g. FIN) to peer.  Socket will be really disconnected
		* when peer sends FIN and acks ours.
		*
		* SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC tcpcb.
		*/
	case PRU_DISCONNECT:
		tp = tcp_disconnect(*tp);
		break;

		/*
		* Accept a connection.  Essentially all the work is
		* done at higher levels; just return the address
		* of the peer, storing through addr.
		*/
	case PRU_ACCEPT:
		inp->in_setpeeraddr(reinterpret_cast<struct sockaddr_in*>(nam), nam_len);
		break;

		/*
		* Mark the connection as being incapable of further output.
		*/
	case PRU_SHUTDOWN:
		dynamic_cast<socket*>(so)->socantsendmore();
		tcp_usrclosed(*tp);
		if (tp)
			error = tcp_output(*tp);
		break;

		/*
		* After a receive, possibly send window update to peer.
		*/
	case PRU_RCVD:
		(void)tcp_output(*tp);
		break;

		/*
		* Do a send by putting data in output queue and updating urgent
		* marker if URG set.  Possibly send more data.
		*/
	case PRU_SEND:
		dynamic_cast<socket*>(so)->so_snd.sbappends(*m);
		error = tcp_output(*tp);
		break;

		/*
		* Abort the TCP.
		*/
	case PRU_ABORT:
		tcp_drop(*tp, ECONNABORTED);
		break;

	case PRU_SENSE:
		return (0);

	case PRU_RCVOOB:
		if ((so->so_oobmark == 0 &&
			(so->so_state & socket::SS_RCVATMARK) == 0) ||
			so->so_options & SO_OOBINLINE ||
			tp->t_oobflags & tcpcb::TCPOOB_HADDATA)
		{
			error = EINVAL;
			break;
		}
		if ((tp->t_oobflags & tcpcb::TCPOOB_HAVEDATA) == 0) {
			error = EWOULDBLOCK;
			break;
		}

		m.reset(new std::vector<byte>(tp->t_iobc));

		if ((reinterpret_cast<int>(nam) & MSG_PEEK) == 0)
			tp->t_oobflags ^= (tcpcb::TCPOOB_HAVEDATA | tcpcb::TCPOOB_HADDATA);
		break;

	case PRU_SENDOOB:
		if (dynamic_cast<socket*>(so)->so_snd.sbspace() < -512) {
			error = ENOBUFS;
			break;
		}

		/*
		* According to RFC961 (Assigned Protocols),
		* the urgent pointer points to the last octet
		* of urgent data.  We continue, however,
		* to consider it to indicate the first octet
		* of data past the urgent section.
		* Otherwise, snd_up should be one lower.
		*/
		dynamic_cast<socket*>(so)->so_snd.sbappends(*m);
		tp->snd_up = tp->snd_una + dynamic_cast<socket*>(so)->so_snd.size();
		tp->t_force = 1;
		error = tcp_output(*tp);
		tp->t_force = 0;
		break;

	case PRU_SOCKADDR:
		//in_setsockaddr(inp, nam);
		break;

	case PRU_PEERADDR:
		//in_setpeeraddr(inp, nam);
		break;

		/*
		* TCP slow timer went off; going through this
		* routine for tracing's sake.
		*/
	case PRU_SLOWTIMO:
		tp = tcp_timers(tp, reinterpret_cast<int>(nam));
		req |= reinterpret_cast<int>(nam) << 8;		/* for debug's sake */
		break;

	default:
		throw std::runtime_error("panic(''tcp_usrreq'')");
		break;
	}
	return (error);
}

int L4_TCP::tcp_attach(socket& so)
{
	/*
	 *	Allocate space for send buffer and receive buffer:
	 *	If space has not been allocated for the socket's send and receive buffers,
	 *	sbreserve sets them both to 8192, the default values of the global variables
	 *	tcp_sendspace and tcp_recvspace (Figure 24.3).
	 *	Whether these defaults are adequate depends on the MSS for each direction of the connection,
	 *	which depends on the MTU. For example, [Comer and Lin 1994] show that anomalous behavior
	 *	occurs if the send buffer is less than three times the MSS, which drastically reduces performance.
	 *	Some implementations have much higher defaults, such as 61,444 bytes, realizing the
	 *	effect these defaults have on performance, especially with higher MTUs (e.g., FOOi and ATM).
	 */
	int error;
	if ((dynamic_cast<socket*>(&so)->so_snd.capacity() == 0 || dynamic_cast<socket*>(&so)->so_rcv.capacity() == 0) &&
		(error = dynamic_cast<socket*>(&so)->soreserve(tcp_sendspace, tcp_recvspace)))
		return (error);

	/*
	 *	Allocate Internet PCB and TCP control block:
	 *	inpcb allocates an Internet PCB and tcp_newtcpcb allocates a TCP control
	 *	block and links it to the PCB.
	 */
	class tcpcb* tp(tcp_newtcpcb(*dynamic_cast<socket*>(&so)));

	/*
	 *	The code with the comment xxx is executed if the allocation in
	 *	tcp_newtcpcb fails. Remember that the PRU_ATTACH request is issued as a result of
	 *	the socket system call, and when a connection request arrives for a listening socket
	 *	(sonewconn). In the latter case the socket flag SS_NOFDREF is set. If this flag is left on,
	 *	the call to sofree by in_pcbdetach releases the socket structure. As we saw in
	 *	tcp_input, this structure should not be released until that function is done with the
	 *	received segment (the dropsocket flag in Figure 29.27). Therefore the current value of
	 *	the SS_NOFDREF flag is saved in the variable nofd when in_pcbdetach is called, and
	 *	reset before tcp_attach returns.
	 */
	if (tp == nullptr) {
		const int nofd(so.so_state & socket::SS_NOFDREF);	/* XXX */
		so.so_state &= ~socket::SS_NOFDREF;	/* don't free the socket yet */
		so.so_state |= nofd;
		return (ENOBUFS);
	}

	/*
	 *	The TCP connection state is initialized to CLOSED.
	 */
	tp->t_state = tcpcb::TCPS_CLOSED;
	return (0);
}

class tcpcb* L4_TCP::tcp_newtcpcb(socket& so)
{
	class tcpcb* tp(new tcpcb(so, tcb));
	/*
   *	The two variables seg_next and seg_prev point to the reassembly queue for out-of-order
   *	segments received for this connection. We discuss this queue in detail in Section 27.9.
   */
	tp->seg_next = tp->seg_prev = reinterpret_cast<struct tcpiphdr*>(tp);

	/*
	*	The maximum segment size to send, t_maxseg, defaults to 512 (tcp_mssdflt).
	*	This value can be changed by the tcp_mss function after an MSS option is received
	*	from the other end. (TCP also sends an MSS option to the other end when a new connection
	*	is established.) The two flags TF REQ_SCALE and TF_REQ_TSTMP are set if the
	*	system is configured to request window scaling and timestamps as defined in RFC 1323
	*	(the global tcp_do_rfc1323 from Figure 24.3, which defaults to 1). The t_inpcb
	*	pointer in the TCP control block is set to point to the Internet PCB passed in by the
	*	caller.
	*/
	tp->t_maxseg = tcp_mssdflt;
	tp->t_flags = tcp_do_rfc1323 ?
		(tcpcb::TF_REQ_SCALE | tcpcb::TF_REQ_TSTMP) :
		0;

	if (tp->t_inpcb == nullptr)
		tp->t_inpcb = dynamic_cast<class inpcb_impl*>(tp);

	/*
	*	The four variables t_srtt, t_rttvar, t_rttmin, and t_rxtcur, described in
	*	Figure 25.19, are initialized. First, the smoothed RTT estimator t_srtt is set to 0
	*	(TCPTV_SRTTBASE), which is a special value that means no RTT measurements have
	*	been made yet for this connection. tcp_xmit_timer recognizes this special value
	*	when the first RTT measurement is made.
	*
	* Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	* rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	* reasonable initial retransmit time.
	*/
	tp->t_srtt = TCPTV_SRTTBASE;

	/*
	*	The smoothed mean deviation estimator t_rttvar is set to 24: 3 (tcp_rttdflt,
	*	from Figure 24.3) times 2 (PR_SLOWHZ) multiplied by 4 (the left shift of 2 bits). Since
	*	this scaled estimator is 4 times the variable rttvar, this value equals 6 clock ticks, or 3
	*	seconds. The minimum RTO, stored in t_rttmin, is 2 ticks (TCPTV MIN).
	*/
	tp->t_rttvar = tcp_rttdflt * PR_SLOWHZ << 2;
	tp->t_rttmin = TCPTV_MIN;

	/*
	*	The current RTO in clock ticks is calculated and stored in t_rxtcur. It is bounded
	*	by a minimum value of 2 ticks (TCPTV_MIN) and a maximum value of 128 ticks
	*	(TCPTV_REXMTMAX). The value calculated as the second argument to TCPT_RANGESET
	*	is 12 ticks, or 6 seconds. This is the first RTO for the connection.
	*	Understanding these C expressions involving the scaled RIT estimators can be a
	*	challenge. It helps to start with the unscaled equation and substitute the scaled variables.
	*	The unscaled equation we're solving is
	*			RTO = srtt + 2*rttvar
	*	where we use the multiplier of 2 instead of 4 to calculate the first RTO.
	*		Remark:	The use of the multiplier 2 instead of 4 appears to be a leftover from the original 4.3850 Tahoe
	*		code (Paxson 1994).
	*	Substituting the two scaling relationships
	*			t_srtt = 8 * srtt
	*			t_rttvar = 4 * rttvar
	*	We get
	*			RTO = t_srtt / 8 + 2 * t_rttvar / 4 = (t_srtt / 8 + t_rttvar) / 2
	*	which is the C code for the second argument to TCPT_RANGESET. In this code the variable
	*	t_rttvar is not used-the constant TCPTV_SRTTDFLT, whose value is 6 ticks, is
	*	used instead, and it must be multiplied by 4 to have the same scale as t_rttvar.
	*/
	TCPT_RANGESET(
		tp->t_rxtcur,
		((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
		TCPTV_MIN,
		TCPTV_REXMTMAX);

	/*
	*	The congestion window (snd_cwnd) and slow start threshold (snd_ssthresh) are
	*	set to l,073,725MO (approximately one gigabyte), which is the largest possible TCP
	*	window if the window scale option is in effect. (Slow start and congestion avoidance
	*	are described in Section 21.6 of Volume 1.) It is calculated as the maximum value for the
	*	window size field in the TCP header (65535, TCP MAXWIN) times 214, where 14 is the
	*	maximum value for the window scale factor (TCP J4AX_WINSHIFT). We'll see that
	*	when a SYN is sent or received on the connection, tcp_rnss resets snd_cwnd to a single
	*	segment.
	*/

	if (tcp_do_rfc1323)
	{
		tp->log_snd_cwnd(tp->snd_cwnd = tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT);
	}
	else
	{
		tp->log_snd_cwnd(tp->snd_cwnd = tp->snd_ssthresh = TCP_MAXWIN);
	}

	/*
	*	The default IP TTL in the Internet PCB is set to 64 (ip_defttl) and the PCB is set
	*	to point to the new TCP control block.
	*	Not shown in this code is that numerous variables, such as the shift variable
	*	t_rxtshift, are implicitly initialized to 0 since the control block is initialized by
	*	bzero.
	*/
	tp->t_inpcb->inp_ip.ip_ttl = L3_impl::IPDEFTTL;
	tp->t_inpcb->inp_ppcb = dynamic_cast<class inpcb_impl*>(tp);
	return tp;
}

class tcpcb* L4_TCP::tcp_timers(class tcpcb* tp, int timer)
{
	switch (timer) {

		/*
		 *	FIN_WAIT_2 and 2MSL Timers:
		*	TCP's TCPT_2MSL counter implements two of TCP's timers.
		*		1.	FIN_WAIT_2 timer. When tcp_input moves from the FIN_WAIT_l state to
		*			the FIN_ WAIT_2 state and the socket cannot receive any more data (implying
		*			the process called close, instead of taking advantage of TCP's half-close with
		*			shutdown), the FIN_WAIT_2 timer is set to 10 minutes (tcp_maxidle). We'll
		*			see that this prevents the connection from staying in the FIN_WAIT_2 state forever.
		*		2.	2MSL timer. When TCP enters the TWE_WAIT state, the 2MSL timer is set to
		*			60 seconds (TCPTV_MSL times 2).
		*
		*	2MSL timer
		*	The puzzling logic in the conditional is because the two different uses of the
		*	TCPT_2MSL counter are intermixed (Exercise 25.4). Let's first look at the TIME_WAIT
		*	state. When the timer expires after 60 seconds, tcp_close is called and the control
		*	blocks are released. We have the scenario shown in Figure 25.11. This figure shows the
		*	series of function calls that occurs when the 2MSL timer expires. We also see that setting
		*	one of the timers for N seconds in the future (2 x N ticks), causes the timer to expire
		*	somewhere between 2 x N - 1 and 2 x N ticks in the future, since the time until the first
		*	decrement of the counter is between 0 and 500 ms in the future.
		*
		*	FIN_WAIT_2 timer:
		*	If the connection state is not TIME_ WAIT, the TCPT_2MSL counter is the
		*	FIN_WAIT_2 timer. As soon as the connection has been idle for more than 10 minutes
		*	(tcp_maxidle) the connection is dosed. But if the connection has been idle for less
		*	than or equal to 10 minutes, the FIN_WAIT_2 timer is reset for 75 seconds in the future.
		*	Figure 25.12 shows the typical scenario.
		*
		* 2 MSL timeout in shutdown went off.  If we're closed but
		* still waiting for peer to close and connection has been idle
		* too long, or if 2MSL time is up from TIME_WAIT, delete connection
		* control block.  Otherwise, check again in a bit.
		*/
	case TCPT_2MSL:
		if (tp->t_state != tcpcb::TCPS_TIME_WAIT && tp->t_idle <= tcp_maxidle)
			tp->t_timer[TCPT_2MSL] = tcp_keepintvl;
		else
			tp = tcp_close(*tp);
		break;

		/*
		* Retransmission timer went off.  Message has not
		* been acked within retransmit interval.  Back off
		* to a longer retransmit interval and retransmit one segment.
		*/
	case TCPT_REXMT:
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
			tcp_drop(*tp, tp->t_softerror ? tp->t_softerror : ETIMEDOUT);
			break;
		}

		tcp_rto_timer_handler(tp);

		/*
		* If losing, let the lower level know and try for
		* a better route.  Also, if we backed off this far,
		* our srtt estimate is probably bogus.  Clobber it
		* so we'll take the next rtt measurement as our srtt;
		* move the current srtt into rttvar to keep the current
		* retransmit times until then.
		*/
		if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
			tp->t_inpcb->in_losing();
			tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
			tp->t_srtt = 0;
		}

		tp->snd_nxt = tp->snd_una;

		/*
		* If timing a segment in this window, stop the timer.
		*/
		tp->t_rtt = 0;


		(void)tcp_output(*tp);
		break;

		/*
		*	Persist Timer:
		*	Force window probe segment:
		*	When the persist timer expires, there is data to send on the connection but TCP has
		*	been stopped by the other end's advertisement of a zero-sized window.
		*	tcp_setpersist calculates the next value for the persist timer and stores it in the
		*	TCPT_PERSIST counter. The flag t_force is set to 1, forcing tcp_output to send 1
		*	byte, even though the window advertised by the other end is 0.
		*
		* Persistence timer into zero window.
		* Force a byte to be output, if possible.
		*/
	case TCPT_PERSIST:
		/*
		* Hack: if the peer is dead/unreachable, we do not
		* time out if the window is closed.  After a full
		* backoff, drop the connection if the idle time
		* (no responses to probes) reaches the maximum
		* backoff that we would use if retransmitting.
		*/
		if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
			(tp->t_idle >= tcp_maxpersistidle || tp->t_idle >= tp->TCP_REXMTVAL() * tcp_totbackoff)) {
			tcp_drop(*tp, ETIMEDOUT);
			break;
		}

		tcp_setpersist(*tp);
		tp->t_force = 1;
		(void)tcp_output(*tp);
		tp->t_force = 0;
		break;

		/*
		*	Connection Establishment and keepalive Timers
		*	TCP's TCPT_KEEP counter implements two timers:
		*		1.	When a SYN is sent, the connection-establishment timer is set to 75 seconds
		*			(TCPTV KEEP INIT). This happens when connect is called, putting a connection
		*			into the SYN_SENT state (active open), or when a connection moves from
		*			the LISTEN to the SYN_RCVD state (passive open). If the connection doesn't
		*			enter the ESTABLISHED state within 75 seconds, the connection is dropped.
		*		2.	When a segment is received on a connection, tcp_input resets the keepalive
		*			timer for that connection to 2 hours (tcp_keepidle), and the t_idle counter
		*			for the connection is reset to 0. This happens for every TCP connection on the
		*			system, whether the keepalive option is enabled for the socket or not. If the
		*			keepalive timer expires (2 hours after the last segment was received on the connection),
		*			and if the socket option is set, a keepalive probe is sent to the other
		*			end. If the timer expires and the socket option is not set, the keepalive timer is
		*			just reset for 2 hours in the future.
		*	Figure 25.16 shows the case for TCP's TCPT_KEEP counter.
		*
		*	Connection-establishment timer expires after 75 seconds:
		*	If the state is less than ESTABLISHED (Figure 24.16), the TCPT_KEEP counter is the
		*	connection-establishment timer. At the label dropit, tcp_drop is called to terminate
		*	the connection attempt with an error of ETIMEOOUT. We'll see that this error is the
		*	default error-if, for example, a soft error such as an ICMP host unreachable was
		*	received on the connection, the error returned to the process will be changed to
		*	EHOSTUNREACH instead of the default.
		*
		* Keep-alive timer went off; send something
		* or drop connection if idle for too long.
		*/
	case TCPT_KEEP:
		if (tp->t_state < tcpcb::TCPS_ESTABLISHED) {
			tcp_drop(*tp, ETIMEDOUT);
			break;
		}

		/*
		*	Keepalive timer expires after 2 hours of Idle time
		*	This timer expires after 2 hours of idle time on every connection, not just ones with
		*	the SOKEEPALIVE socket option enabled. If the socket option is set, probes are sent
		*	only if the connection is in the ESTABLISHED or CLOSE_WAIT states (Figure 24.15).
		*	Once the process calls close (the states greater than CLOSE_WAIT), keepalive probes
		*	are not sent, even if the connection is idle for 2 hours.
		*/
		if (tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE &&
			tp->t_state <= tcpcb::TCPS_CLOSE_WAIT) {

			/*
			*	Drop connection when no response:
			*	If the total idle time for the connection is greater than or equal to 2 hours
			*	(tcp_keepidle) plus 10 minutes (tcp_maxidle}, the connection is dropped. This
			*	means that TCP has sent its limit of nine keepalive probes, 75 seconds apart
			*	(tcp_keepintvl), with no response. One reason TCP must send multiple keepalive
			*	probes before considering the connection dead is that the ACKs sent in response do not
			*	contain data and therefore are not reliably transmitted by TCP. An ACK that is a
			*	response to a keepalive probe can get lost.
			*/
			if (tp->t_idle >= tcp_keepidle + tcp_maxidle) {
				tcp_drop(*tp, ETIMEDOUT);
				break;
			}

			/*
			*	Send a keepalive probe:
			*	If TCP hasn't reached the keepalive limit, tcp_respond sends a keepalive packet.
			*	The acknowledgment field of the keepalive packet (the fourth argument to
			*	tcp_respond) contains rcv _nxt, the next sequence number expected on the connection.
			*	The sequence number field of the keepalive packet (the fifth argument) deliberately
			*	contains snd_una minus l, which is the sequence number of a byte of data that
			*	the other end has already acknowledged (Figure 24.17). Since this sequence number is
			*	outside the lvi.ndow, the other end must respond with an ACK, specifying the next
			*	sequence number it expects.
			*
			* Send a packet designed to force a response
			* if the peer is up and reachable:
			* either an ACK if the connection is still alive,
			* or an RST if the peer has closed the connection
			* due to timeout or reboot.
			* Using sequence number tp->snd_una-1
			* causes the transmitted zero-length segment
			* to lie outside the receive window;
			* by the protocol spec, this requires the
			* correspondent TCP to respond.
			*/
			tcp_respond(tp, tp->t_template, nullptr, std::vector<byte>::iterator(), tp->rcv_nxt, tp->snd_una - 1, 0);
			tp->t_timer[TCPT_KEEP] = tcp_keepintvl;
		}

		/*
		*	Reset keepalive timer
		*	If the socket option is not set or the connection state is greater than CLOSE_WAIT,
		*	the keepalive timer for this connection is reset to 2 hours (tcp_keepidle).
		*		Remark:	Unfortunately the counter tcps_keepdrops (line 253) counts both uses of the TCPT_KEEP
		*				counter: the connection-establishment timer and the keepalive timer.
		*/
		else
			tp->t_timer[TCPT_KEEP] = tcp_keepidle;
		break;
	}
	return (tp);
}

inline void L4_TCP::tcp_setpersist(class tcpcb& tp)
{
	if (tp.t_timer[TCPT_REXMT])
		throw std::runtime_error("tcp_output REXMT");
	/*
	* Start/restart persistence timer.
	*/
	TCPT_RANGESET(
		tp.t_timer[TCPT_PERSIST],
		(((tp.t_srtt >> 2) + tp.t_rttvar) >> 1) * tcp_backoff(tp.t_rxtshift),
		TCPTV_PERSMIN,
		TCPTV_PERSMAX);
	if (tp.t_rxtshift < TCP_MAXRXTSHIFT)
		tp.t_rxtshift++;
}

int L4_TCP::tcp_backoff(const int backoff) // TODO: move to tahoe
{
	if (0 <= backoff && backoff <= 5)
		return 0x1 << backoff;
	else if (6 <= backoff && backoff <= TCP_MAXRXTSHIFT)
		return 64;
	return 0;
}

class tcpcb* L4_TCP::tcp_disconnect(class tcpcb& tp)
{
	socket* so(dynamic_cast<socket*>(tp.t_inpcb->inp_socket));
	if (tp.t_state < tcpcb::TCPS_ESTABLISHED)
		tcp_close(tp);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		tcp_drop(tp, 0);
	else {
		so->soisdisconnecting();
		so->so_rcv.sbdrops();
		tcp_usrclosed(tp);
		if (&tp)
			(void)tcp_output(tp);
	}
	return (&tp);
}

void L4_TCP::tcp_usrclosed(class tcpcb& tp)
{
	switch (tp.t_state) {

	case tcpcb::TCPS_CLOSED:
	case tcpcb::TCPS_LISTEN:
	case tcpcb::TCPS_SYN_SENT:
		tp.t_state = tcpcb::TCPS_CLOSED;
		tcp_close(tp);
		break;

	case tcpcb::TCPS_SYN_RECEIVED:
	case tcpcb::TCPS_ESTABLISHED:
		tp.t_state = tcpcb::TCPS_FIN_WAIT_1;
		break;

	case tcpcb::TCPS_CLOSE_WAIT:
		tp.t_state = tcpcb::TCPS_LAST_ACK;
		break;
	}
	if (&tp && tp.t_state >= tcpcb::TCPS_FIN_WAIT_2)
		dynamic_cast<socket*>(tp.t_inpcb->inp_socket)->soisdisconnected();

	return;
}

void L4_TCP::tcp_drop(class tcpcb& tp, const int err)
{
	if (tp.t_inpcb) {
		socket* so(dynamic_cast<socket*>(tp.t_inpcb->inp_socket));

		/*
		*	If TCP has received a SYN, the connection is synchronized and an RST must be sent
		*	to the other end. This is done by setting the state to CLOSED and calling tcp_output.
		*	In Figure 24.16 the value of tcp_outflags for the CLOSED state includes the RST flag.
		*/
		if (tp.TCPS_HAVERCVDSYN()) {
			tp.t_state = tcpcb::TCPS_CLOSED;
			(void)tcp_output(tp);
		}

		/*
		*	If the error is ETIMEDOUT but a soft error was received on the connection (e.g.,
		*	EHOSTUNREACH), the soft error becomes the socket error, instead of the less specific
		*	ETIMEDOUT.
		*/
		int newErr(err);
		if (newErr == ETIMEDOUT && tp.t_softerror)
			newErr = tp.t_softerror;
		so->so_error = newErr;

		/*	tcp_close finishes closing the socket.	*/
		return (void)tcp_close(tp);
	}
}

class tcpcb* L4_TCP::tcp_close(class tcpcb& tp)
{
	/*
	*	Check If enough data sent to update statistics
	*	The default send buffer size is 8192 bytes (sb_hiwat), so the first test is whether
	*	131,072 bytes (16 full buffers) have been transferred across the connection. The initial
	*	send sequence number is compared to the maximum sequence number sent on the connection.
	*	Additionally, the socket must have a cached route and that route cannot be the
	*	default route. (See Exercise 19.2.)
	*		Remark:	Notice there is a small chance for an error in the first test, because of sequence number wrap, if
	*				the amount of data transferred is within N x 232 and N x 232 + 131072, for any N greater than 1.
	*				But few connections (today) transfer 4 gigabytes of data.
	*				Despite the prevalence of default routes in the Internet, this information is still useful to maintain
	*				in the routing table. If a host continuaJJy exchanges data with another host (or network),
	*				even if a default route can be used, a host-specific or network-specific route can be entered into
	*				the routing table with the route command just to maintain this information access connections.
	*				(See Exercise 19.2.) This information is lost when the system is rebooted.
	*
	* If we sent enough data to get some meaningful characteristics,
	* save them in the routing entry.  'Enough' is arbitrarily
	* defined as the sendpipesize (default 4K) * 16.  This would
	* give us 16 rtt samples assuming we only get one sample per
	* window (the usual case on a long haul net).  16 samples is
	* enough for the srtt filter to converge to within 5% of the correct
	* value; fewer samples and we could save a very bogus rtt.
	*
	* Don't update the default route's characteristics and don't
	* update anything that the user "locked".
	*/
	class inpcb_impl* inp(tp.t_inpcb);
	struct L3::rtentry* rt;
	socket* so(dynamic_cast<socket*>(inp->inp_socket));

	if (tcpcb::SEQ_LT(tp.iss + dynamic_cast<socket*>(so)->so_snd.capacity() * 16, tp.snd_max) &&
		(rt = inp->inp_route.ro_rt) &&
		reinterpret_cast<struct sockaddr_in*>(rt->rt_key())->sin_addr.s_addr != INADDR_ANY)
	{
		u_long i(0);
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTT) == 0)
			rt->rt_rmx.rmx_rtt =
			(rt->rt_rmx.rmx_rtt &&
				(i = tp.t_srtt * (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE)))) ?
			/*
			* filter this update to half the old & half
			* the new values, converting scale.
			* See route.h and tcp_var.h for a
			* description of the scaling constants.
			*/
			(rt->rt_rmx.rmx_rtt + i) / 2 :
		i;
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTTVAR) == 0)
			rt->rt_rmx.rmx_rttvar =
			(rt->rt_rmx.rmx_rttvar &&
				(i = tp.t_rttvar * (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE)))) ?
			(rt->rt_rmx.rmx_rttvar + i) / 2 :
			i;

		/*
		* update the pipelimit (ssthresh) if it has been updated
		* already or if a pipesize was specified & the threshhold
		* got below half the pipesize.  I.e., wait for bad news
		* before we start updating, then update on both good
		* and bad news.
		*/
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_SSTHRESH) == 0 &&
			(i = tp.snd_ssthresh) &&
			rt->rt_rmx.rmx_ssthresh ||
			i < (rt->rt_rmx.rmx_sendpipe / 2))
		{
			/*
			* convert the limit from user data bytes to
			* packets then to packet data bytes.
			*/
			if ((i = (i + tp.t_maxseg / 2) / tp.t_maxseg) < 2)
				i = 2;

			i *= static_cast<u_long>(tp.t_maxseg + sizeof(struct tcpiphdr));

			rt->rt_rmx.rmx_ssthresh =
				rt->rt_rmx.rmx_ssthresh ?
				(rt->rt_rmx.rmx_ssthresh + i) / 2 :
				i;
		}
	}

	/* free the reassembly queue, if any */
	struct tcpiphdr* t(tp.seg_next),
		* t_old;
	while (t)
	{
		t_old = t;
		t = t->ti_next();
		t_old->remque();
		delete t_old;
	}

	if (tp.t_template)
		delete tp.t_template;

	if (inp->inp_ppcb != inp) {
		delete inp->inp_ppcb;
		inp->inp_ppcb = nullptr;
	}

	dynamic_cast<socket*>(so)->soisdisconnected();

	/* clobber input pcb cache if we're closing the cached connection */
	if (inp == tcp_last_inpcb)
		tcp_last_inpcb = &tcb;

	delete inp;
	return nullptr;
}

/************************************************************************/
/*				  L4_TCP_impl pr_output						            */
/************************************************************************/

L4_TCP::tcp_output_args::tcp_output_args(tcpcb& tp) : tp(tp) { }

int L4_TCP::again(tcpcb& tp, const bool idle, socket& so)
{
	/*
	 *	Determine if a Segment Should be Sent:
	 *	Sometimes tcp_output is called but a segment is not generated. For example, the
	 *	PRU_RCVD request is generated when the socket layer removes data from the socket's
	 *	receive buffer, passing the data to a process. It is possible that the process removed
	 *	enough data that TCP should send a segment to the other end with a new window
	 *	advertisement, but this is just a possibility, not a certainty. The first half of tcp_output
	 *	determines if there is a reason to send a segment to the other end. If not, the function
	 *	returns without sending a segment.
	 *
	 *	off is the offset in bytes from the beginning of the send buffer of the first data byte
	 *	to send. The first off bytes in the send buffer, starting with snd_una, have already
	 *	been sent and are waiting to be ACKed.
	 *		win is the minimum of the window advertised by the receiver (snd_wnd) and the
	 *	congestion window (snd_cwnd).
	 */
	int off(tp.snd_nxt - tp.snd_una);
	long win(std::min(tp.snd_wnd, tp.snd_cwnd));

	/*
	 *	The value of tcp_outflags array that is fetched and stored in flags depends on the current
	 *	state of the connection. flags contains the combination of the TH_ACK, TH_FIN, TH_RST,
	 *	and TH_SYN flag bits to send to the other end.The other two flag bits, TH_PUSH and TH_URG,
	 *	will be logically ORed into flags if necessary before the segment is sent.
	 */
	int flags(tp.tcp_outflags());

	/*
	 *	The flag t_force is set nonzero when the persist timer expires or when out-of-band
	 *	data is being sent. These two conditions invoke tcp_output as follows:
	 *		tp->t_force = l;
	 *		error = tcp_output(tp);
	 *		tp->t_force = O;
	 *	This forces TCP to send a segment when it normally wouldn't send anything.
	 *
	* If in persist timeout with window of 0, send 1 byte.
	* Otherwise, if window is small but nonzero
	* and timer expired, we will send what we can
	* and go to transmit state.
	*/
	if (tp.t_force)
		/*
		 *	If win is 0, the connection is in the persist state(since t_force is nonzero).
		 *	The FIN flag is cleared if there is more data in the socket's send buffer.
		 *	win must be set to 1 byte to force out a single byte.
		 */
		if (win == 0) {

			/*
			* If we still have some data to send, then
			* clear the FIN bit.  Usually this would
			* happen below when it realizes that we
			* aren't sending all the data. However,
			* if we have exactly 1 byte of unset data,
			* then it won't clear the FIN bit below,
			* and if we are in persist state, we wind
			* up sending the packet without recording
			* that we sent the FIN bit.
			*
			* We can't just blindly clear the FIN bit,
			* because if we don't have any more data
			* to send then the probe will be the FIN
			* itself.
			*/
			if (off < static_cast<int>(so.so_snd.size()))
				flags &= ~tcphdr::TH_FIN;

			/*
			*	win must be set to 1 byte to force out a single byte.
			*/
			win = 1;
		}
	/*
	 *	If win is nonzero, out-of-band data is being sent, so the persist timer is cleared and
	 *	the exponential backoff index, t_rxtshift, is set to 0.
	 */
		else {
			tp.t_timer[TCPT_PERSIST] = 0;
			tp.t_rxtshift = 0;
		}

	/*
	 *	Calculate amount of data to send:
	 *	len is the minimum of the number of bytes in the send buffer and win (which is
	 *	the minimum of the receiver's advertised window and the congestion window, perhaps
	 *	1 byte if output is being forced). off is subtracted because that many bytes at the
	 *	beginning of the send buffer have already been sent and are awaiting acknowledgment.
	 */
	long len(std::min(static_cast<long>(so.so_snd.size()), win) - off);

	/*
	*	Check for window shrink:
	*	One way for len to be less than 0 occurs if the receiver shrinks the window, that is,
	*	the receiver moves the right edge of the window to the left. For example, assume that
	*	first the receiver advertises a window of 6 bytes and TCP transmits a segment with
	*	bytes 4, 5, and 6. TCP immediately transmits another segment with bytes 7, 8, and 9.
	*	Then an ACK is received with an acknowledgment field of 7 (acknowledging all data
	*	up through and including byte 6) but with a window of 1. The receiver has shrunk the
	*	window.
	*	Performing the calculations of tcp_output up to now, after the window is shrunk, we
	*	have:
	*		off = snd_nxt - snd_una = 10 - 7 = 3
	*		win = 1
	*		len = min<so_snd.sb_cc, win) - off * min(3, 1) - 3 = -2
	*	assuming the send buffer contains only bytes 7, 8, and 9.
	*		Remark:	Both RFC 793 and RFC 1122 strongly discourage shrinking the window. Nevertheless,
	*				implementations must be prepared for this. Handling scenarios such as this comes
	*				under the Robustness Principle, first mentioned in RFC 791:
	*					"Be liberal in what you accept, and conservative in what you send."
	*
	*	Another way for len to be less than 0 occurs if the FIN has been sent but not acknowledged
	*	and not retransmitted. We take the previous example, but assuming the final segment with
	*	bytes 7, 8, and 9 is acknowledged, which sets snd_una to 10. The process then doses the
	*	connection, causing the FIN to be sent. We'll see later that when the FIN is sent, snd_nxt
	*	is incremented by 1 (since the FIN takes a sequence number), which in this example sets
	*	snd_nxt to 11. The sequence number of the FIN is 10. Performing the calculations, we have
	*		off = snd_nxt - snd_una ~ 11 - 10 = 1
	*		win = 6
	*		len = min{so_snd.sb_cc, win) - off = rnin(O, 6) - 1 = -1
	*	We assume that the receiver advertises a window of 6, which makes no difference, since
	*	the number of bytes in the send buffer (O) is less than this.
	*/
	if (len < 0) {

		/*
		*	Enter persist state:
		*	len is set to 0.
		* If FIN has been sent but not acked,
		* but we haven't been called to retransmit,
		* len will be -1.  Otherwise, window shrank
		* after we sent into it.  If window shrank to 0,
		* cancel pending retransmit and pull snd_nxt
		* back to (closed) window.  We will enter persist
		* state below.  If the window didn't close completely,
		* just wait for an ACK.
		*/
		len = 0;

		/*
		*	If the advertised window is 0, any pending retransmission is canceled by setting the
		*	retransmission timer to 0. snd_nxt is also pulled to the left of the window by setting
		*	it to the value of snd_una. The connection will enter the persist state later in this
		*	function, and when the receiver finally opens its window, TCP starts retransmitting
		*	from the left of the window.
		*/
		if (win == 0) {
			tp.t_timer[TCPT_REXMT] = 0;
			tp.snd_nxt = tp.snd_una;
		}
	}

	/*
	*	Send one segment at a time:
	*	If the amount of data to send exceeds one segment, len is set to a single segment
	*	and the sendalot flag is set to 1. This causes another loop through tcp_output
	*	after the segment is sent.
	*/
	bool sendalot(false);
	if (len > tp.t_maxseg) {
		len = tp.t_maxseg;
		sendalot = true;
	}

	/*
	*	Turn off FIN flag If send buffer not emptied:
	*	If the send buffer is not being emptied by this output operation, the FIN flag must
	*	be cleared (in case it is set in flags). For example, assume the first 512-byte
	*	segment has already been sent (and is waiting to be
	*	acknowledged) and TCP is about to send the next 512-byte segment (bytes 512-1024).
	*	There is still 1 byte left in the send buffer (byte 1025) and the process closes the connection.
	*	len equals 512 (one segment), and the C expression becomes
	*		SEQ_LT(l025, 1026}
	*	which is true, so the FIN flag is cleared. If the FIN flag were mistakenly left on, TCP
	*	couldn't send byte 1025 to the receiver.
	*/
	if (tcpcb::SEQ_LT(tp.snd_nxt + len, tp.snd_una + so.so_snd.size()))
		flags &= ~tcphdr::TH_FIN;

	/*
	*	Calculate window advertisement:
	*	win is set to the amount of space available in the receive buffer, which becomes
	*	TCP's window advertisement to the other end. Be aware that this is the second use of
	*	this variable in this function. Earlier it contained the maximum amount of data TCP
	*	could send, but for the remainder of this function it contains the receive window advertised
	*	by this end of the connection.
	*	The silly window syndrome (called SWS and described in Section 22.3 of Volume 1)
	*	occurs when small amounts of data, instead of full-sized segments, are exchanged
	*	across a connection. It can be caused by a receiver who advertises small windows and
	*	by a sender who transmits small segments. Correct avoidance of the silly window syndrome
	*	must be performed by both the sender and the receiver.
	*/
	win = so.so_rcv.sbspace();

	/*
	* Sender silly window avoidance.  If connection is idle
	* and can send all data, a maximum segment,
	* at least a maximum default-size segment do it,
	* or are forced, do it; otherwise don't bother.
	* If peer's buffer is tiny, then send
	* when window is at least half open.
	* If retransmitting (possibly after persist timer forced us
	* to send into a small window), then must resend.
	*/
	if (len) {

		/*
		*	If a full-sized segment can be sent, it is sent.
		*/
		if (len == tp.t_maxseg)
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If an ACK is not expected (idle is true), or if the Nagle algorithm is disabled
		*	(TF_NODELAY is true) and TCP is emptying the send buffer, the data is sent. The Nagle
		*	algorithm (Section 19.4 of Volume 1) prevents TCP from sending less than a full-sized
		*	segment when an ACK is expected for the connection. It can be disabled using the
		*	TCP_NODELAY socket option. For a normal interactive connection (e.g., Telnet or
		*	Rlogin), if there is unacknowledged data, this if statement is false, since the Nagle
		*	algorithm is enabled by default .
		*/
		else if ((idle || tp.t_flags & tcpcb::TF_NODELAY) &&
			len + off >= static_cast<long>(so.so_snd.size()))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If output is being forced by either the persist timer or sending out-of-band data,
		*	some data is sent.
		*/
		else if (tp.t_force)
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the receiver's window is at least half open, data is sent. This is to deal with peers
		*	that always advertise tiny windows, perhaps smaller than the segment size. The variable
		*	max_sndwnd is calculated by tcp_input as the largest window advertisement ever advertised
		*	by the other end. It is an attempt to guess the size of the other end's receive buffer
		*	and assumes the other end never reduces the size of its receive buffer.
		*/
		else if (len >= static_cast<long>(tp.max_sndwnd / 2))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the retransmission timer expired, then a segment must be sent. snd_max is the
		*	highest sequence number that has been transmitted. We saw that when the retransmission
		*	timer expires, snd_nxt is set to snd_una, that is, snd_nxt is moved to the left edge
		*	of the window, making it less than snd_max.
		*/
		else if (tcpcb::SEQ_LT(tp.snd_nxt, tp.snd_max))
			return send(tp, idle, so, sendalot, off, flags, win, len);
	}

	/*
	*	The next portion of tcp_output determines if TCP must send a segment just to advertise a
	*	new window to the other end. This is called a window update.
	*
	* Compare available window to amount of window
	* known to peer (as advertised window less
	* next expected input). If the difference is at least two
	* max size segments, or at least 50% of the maximum possible
	* window, then want to send a window update to peer.
	*/
	if (win > 0) {

		/*
		*	The expression
		*		min(win, (long)TCP_MAXWIN << tp->rcv_scale)
		*	is the smaller of the amount of available space in the socket's receive buffer (win) and
		*	the maximum size of the window allowed for this connection. This is the maximum
		*	window TCP can currently advertise to the other end. The expression
		*		(tp->rcv_adv - tp->rcv_nxt)
		*	is the number of bytes remaining in the last window advertisement that TCP sent to the
		*	other end. Subtracting this from the maximum window yields adv, the number of bytes by
		*	which the window has opened. rcv_nxt is incremented by tcp_input
		*	when data is received in sequence, and rev_adv is incremented by tcp_output when the
		*	edge of the advertised window moves to the right.
		*	For example, assume that a segment with bytes 4, 5, and 6 is received and that these
		*	three bytes are passed to the process. The value of adv is 3, since there are 3 more
		*	bytes of the receive space (bytes 10, 11, and 12) for the other end to fill.
		*
		* "adv" is the amount we can increase the window,
		* taking into account that we are limited by
		* TCP_MAXWIN << tp->rcv_scale.
		*/
		long adv(std::min(
			win,
			static_cast<long>(TCP_MAXWIN << tp.rcv_scale)) - (tp.rcv_adv - tp.rcv_nxt));

		/*
		*	If the window has opened by two or more segments, a window update is sent.
		*	When data is received as full-sized segments, this code causes every other received
		*	segment to be acknowledged: TCP's ACK-every-other-segment property. (We show an
		*	example of this shortly.)
		*/
		if (adv >= static_cast<long>(2 * tp.t_maxseg))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the window has opened by at least 50% of the maximum possible window (the
		*	socket's receive buffer high-water mark), a window update is sent.
		*/
		else if (2 * adv >= static_cast<long>(so.so_rcv.capacity()))
			return send(tp, idle, so, sendalot, off, flags, win, len);
	}

	/*
	*	Check whether various flags require TCP to send a segment.
	*	Send if we owe peer an ACK.
	*	If an immediate ACK is required, a segment is sent. The TF_ACKNOW flag is set by
	*	various functions: when the 200-ms delayed ACK timer expires, when a segment is
	*	received out of order (for the fast retransmit algorithm), when a SYN is received during
	*	the three-way handshake, when a persist probe is received, and when a FIN is received.
	*/
	if (tp.t_flags & tcpcb::TF_ACKNOW)
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If flags specifies that a SYN or RST should be sent, a segment is sent.
	*/
	else if (flags & (tcphdr::TH_SYN | tcphdr::TH_RST))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If the urgent pointer, snd_up, is beyond the start of the send buffer, a segment is
	*	sent. The urgent pointer is set by the PRU_SENDOOB request (Figure 30.9).
	*/
	else if (tcpcb::SEQ_GT(tp.snd_up, tp.snd_una))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If flags specifies that a FIN should be sent, a segment is sent only if the FIN has
	*	not already been sent, or if the FIN is being retransmitted. The flag TF_SENTFIN is set
	*	later in this function when the FIN is sent.
	*/
	else if (flags & tcphdr::TH_FIN &&
		((tp.t_flags & tcpcb::TF_SENTFIN) == 0 || tp.snd_nxt == tp.snd_una))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	At this point in tcp_output there is no need to send a segment. Next, we show the final
	*	piece of code before tcp_output returns.
	*	If there is data in the send buffer to send (so_snd.sb_cc is nonzero) and both the
	*	retransmission timer and the persist timer are off, turn the persist timer on. This scenario
	*	happens when the window advertised by the other end is too small to receive a
	*	full-sized segment, and there is no other reason to send a segment.
	*
	* TCP window updates are not reliable, rather a polling protocol
	* using ''persist'' packets is used to insure receipt of window
	* updates. The three ''states'' for the output side are:
	*	idle				not doing retransmits or persists
	*	persisting			to move a small or zero window
	*	(re)transmitting	and thereby not persisting
	*
	* tp->t_timer[TCPT_PERSIST]
	*	is set when we are in persist state.
	* tp->t_force
	*	is set when we are called to send a persist packet.
	* tp->t_timer[TCPT_REXMT]
	*	is set when we are retransmitting
	* The output side is idle when both timers are zero.
	*
	* If send window is too small, there is data to transmit, and no
	* retransmit or persist is pending, then go to persist state.
	* If nothing happens soon, send when timer expires:
	* if window is nonzero, transmit what we can,
	* otherwise force out a byte.
	*/
	if (so.so_snd.size() && tp.t_timer[TCPT_REXMT] == 0 &&
		tp.t_timer[TCPT_PERSIST] == 0)
	{
		tp.t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	/*
	*	No reason to send a segment, just return.
	*/
	return (0);


}

int L4_TCP::send(tcpcb& tp, const bool idle, socket& so, bool sendalot, int& off, int& flags, long& win, long& len)
{
	/*
	*	The TCP options are built in the array opt, and the integer optlen keeps a count of
	*	the number of bytes accumulated (since multiple options can be sent at once).
	*	If	the SYN flag bit is set, snd_nxt is set to the initial send sequence number (iss).
	*	If	TCP is performing an active open, iss is set by the PRU_CONNECT request when the
	*		TCP control block is created.
	*	If	this is a passive open, tcp_input creates the TCP control block and sets iss.
	*	In both cases, iss is set from the global tcp_iss.
	*
	* Before ESTABLISHED, force sending of initial options
	* unless TCP set not to do any options.
	* NOTE: we assume that the IP/TCP header plus TCP options
	* always fit in a single mbuf, leaving room for a maximum
	* link header, i.e.
	*	max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MHLEN
	*/
	unsigned optlen(0);
	unsigned hdrlen(sizeof(tcpiphdr));
	u_char opt[MAX_TCPOPTLEN];

	if (flags & tcphdr::TH_SYN) {
		tp.snd_nxt = tp.iss;

		/*
		*	The flag TF_NOOPT is checked, but this flag is never enabled and there is no way to
		*	turn it on. Hence, the MSS option is always sent with a SYN segment.
		*		Remark: In the Net/1 version of tcp_newtcpcb, the comment "send options!" appeared on the line
		*				that initialized t_f lags to 0. The TF _NOOPT flag is probably a historical artifact from
		*				a preNet/1 system that had problems inter-operating with other hosts when it sent the
		*				MSS option, so the default was to not send the option.
		*/
		if ((tp.t_flags & tcpcb::TF_NOOPT) == 0) {

			/*
			*	Build MSS option:
			*	opt[0] is set to 2 (TCPOPTJIAXSEG) and opt [1] is set to 4, the length of the MSS option in bytes.
			*/
			opt[0] = TCPOPT_MAXSEG;
			opt[1] = 4;

			/*
			*	The function tcp_mss calculates the MSS to announce to the other end;
			*	The 16-bit MSS is stored in opt [2] and opt [3] by bcopy.
			*	Notice that Net/3 always sends an MSS announcement with the SYN for a connection.
			*/
			u_short mss(htons(static_cast<u_short>(tcp_mss(tp, 0))));
			std::memcpy(&opt[2], &mss, sizeof(mss));
			optlen = 4;

			/*
			*	Should window scale option be sent?
			*	If TCP is to request the window scale option, this option is sent only if this is an
			*	active open (TH_ACK is not set) or if this is a passive open and the window scale option
			*	was received in the SYN from the other end. Recall that t_flags was set to
			*	TF_REQ_SCALE | TF_REQ_TSTMP when the TCP control block was created, if the global variable
			*	tcp_do_rfc1323 was nonzero (its default value).
			*/
			if ((tp.t_flags & tcpcb::TF_REQ_SCALE) && ((flags & tcphdr::TH_ACK) == 0 || (tp.t_flags & tcpcb::TF_RCVD_SCALE))) {

				/*
				*	Build window scale option:
				*	Since the window scale option occupies 3 bytes, a 1-byte NOP is stored before the option,
				*	forcing the option length to be 4 bytes. This causes the data in the segment that follows
				*	the options to be aligned on a 4-byte boundary.
				*	If this is an active open, request_r_scale is calculated by the PRU_CONNECT request.
				*	If this is a passive open, the window scale factor is calculated by tcp_input when the
				*	SYN is received.
				*	RFC 1323 specifies that if TCP is prepared to scale windows it should send this option
				*	even if its own shift count is 0. This is because the option serves two purposes:
				*	1. to notify the other end that it supports the option
				*	2. to announce its shift count.
				*	Even though TCP may calculate its own shift count as 0, the other end might want to use a
				*	different value.
				*/
				*reinterpret_cast<u_long*>(&opt[optlen]) = htonl(TCPOPT_NOP << 24 | TCPOPT_WINDOW << 16 | TCPOLEN_WINDOW << 8 | tp.request_r_scale);
				optlen += 4;
			}
		}
	}

	/*
	*	The next part of tcp_output finishes building the options in the outgoing segment.
	*
	*	Should timestamp option be sent?
	*	If the following three conditions are all true, a timestamp option is sent:
	*	(1) TCP is configured to request the timestamp option,
	*	(2) the segment being formed does not contain the RST flag, and
	*	(3) either this is an active open (i.e., flags specifies the SYN flag but not the
	*		ACK flag) or TCP has received a timestamp from the other end (TF RCVD_TSTMP).
	*	Unlike the MSS and window scale options, a timestamp option can be sent with every
	*	segment once both ends agree to use the option.
	*
	* Send a timestamp and echo-reply if this is a SYN and our side
	* wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	* and our peer have sent timestamps in our SYN's.
	*/
	if ((tp.t_flags & (tcpcb::TF_REQ_TSTMP | tcpcb::TF_NOOPT)) == tcpcb::TF_REQ_TSTMP &&
		(flags & tcphdr::TH_RST) == 0 &&
		((flags & (tcphdr::TH_SYN | tcphdr::TH_ACK)) == tcphdr::TH_SYN ||
			(tp.t_flags & tcpcb::TF_RCVD_TSTMP)))
	{
		u_long* lp(reinterpret_cast<u_long*>(&opt[optlen]));

		/*
		*	Build timestamp option:
		*	The timestamp option (Section 26.6) consists of 12 bytes (TCPOLEN_TSTAMP_APPA).
		*	The first 4 bytes are Ox0101080a (the constant TCPOPT_TSTAMP_HDR).
		*	The timestamp value is taken from tcp_now (the number of 500-ms clock ticks
		*	since the system was initialized), and the timestamp echo reply is taken from
		*	ts_recent, which is set by tcp_input.
		*	Form timestamp option as shown in appendix A of RFC 1323.
		*/
		*lp++ = htonl(TCPOPT_TSTAMP_HDR);
		*lp++ = htonl(tcp_now);
		*lp = htonl(tp.ts_recent);
		optlen += TCPOLEN_TSTAMP_APPA;
	}

	hdrlen += optlen;

	/*
	*	Check If options have overflowed segment:
	*	The size of the TCP header is incremented by the number of option bytes (optlen).
	*	If the amount of data to send (len) exceeds the MSS minus the size of the options
	*	(opt len), the data length is decreased accordingly and the sendalot flag is set,
	*	to force another loop through this function after this segment is sent.
	*	The MSS and window scale options only appear in SYN segments, which Net/3 always
	*	sends without data, so this adjustment of the data length doesn't apply. When the
	*	timestamp option is in use, however, it appears in all segments. This reduces the
	*	amount of data in each full-sized data segment from the announced MSS to the
	*	announced MSS minus 12 bytes.
	*
	* Adjust data length if insertion of options will
	* bump the packet length beyond the t_maxseg length.
	*/
	if (len > static_cast<long>(tp.t_maxseg - optlen)) {
		len = tp.t_maxseg - optlen;
		sendalot = true;
		flags &= ~tcphdr::TH_FIN;
	}

	/*
	*	Allocate an mbuf for IP and TCP headers:
	*	An mbuf with a packet header is allocated by MGETHDR. This is for the IP and TCP
	*	headers, and possibly the data (if there's room). Although tcp_output is often called
	*	as part of a system call (e.g., write) it is also called at the software interrupt level by
	*	tcp_input, and as part of the timer processing. Therefore M_DONTWAIT is specified.
	*	If an error is returned, a jump is made to the label out. This label is near the end of the
	*	function.
	*/
	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(hdrlen + sizeof(struct L2::ether_header) + len));
	if (m == nullptr)
		return out(tp, ENOBUFS);

	std::vector<byte>::iterator it(m->begin() + sizeof(struct L2::ether_header));

	if (len) {

		/*
		*	Copy data Into mbuf:
		*	If the amount of data is less than 44 bytes (100-40-16, assuming no TCP options),
		*	the data is copied directly from the socket send buffer into the new packet header mbuf
		*	by m_copydata. Otherwise m_copy creates a new mbuf chain with the data from the
		*	socket send buffer and this chain is linked to the new packet header mbuf. Recall our
		*	description of m_copy in Section 2.9, where we showed that if the data is in a cluster,
		*	m_copy just references that cluster and doesn't make a copy of the data.
		*/
		//std::copy(so.so_snd.begin(), so.so_snd.begin() + len, it + hdrlen);
		auto slot = boost::make_iterator_range(it + hdrlen, it + hdrlen + len);
		so.so_snd.sbfill(slot);


		/*
		*	Set PSH flag:
		*	If TCP is sending everything it has from the send buffer, the PSH flag is set.
		*	As the comment indicates, this is intended for receiving systems that only
		*	pass received data to an application when the PSH flag is received or when
		*	a buffer fills. We'll see in tcp_input that Net/3 never holds data in a
		*	socket receive buffer waiting for a received PSH flag.
		*
		* If we're sending everything we've got, set PUSH.
		* (This will keep happy those implementations which only
		* give data to the user when a buffer fills or
		* a PUSH comes in.)
		*/
		if (off + len == so.so_snd.size())
			flags |= tcphdr::TH_PUSH;
	}

	struct tcpiphdr* ti(reinterpret_cast<struct tcpiphdr*>(&m->data()[it - m->begin()]));

	/*
	*	Copy IP and TCP header templates Into mbuf:
	*	The template of the IP and TCP headers is copied from t_template into the mbuf
	*	by bcopy. This template was created by tcp_template.
	*/
	if (tp.t_template == nullptr)
		throw std::runtime_error("tcp_output: t_template is null!");
	std::memcpy(ti, tp.t_template, sizeof(struct tcpiphdr));

	/*
	*	The next part of tcp_output fills in some remaining fields in the TCP header.
	*
	*	Decrement snd_nxt If FIN Is being retransmitted:
	*	If TCP has already transmitted the FIN, the send sequence space appears.
	*	Therefore, if the FIN flag is set, and if the TF SENTFIN flag is set, and if snd_nxt
	*	equals snd_max, TCP knows the FIN is being retransmitted. We'll see shortly that when
	*	a FIN is sent, snd_nxt is incremented 1 one (since the FIN occupies a sequence number),
	*	so this piece of code decrements snd_nxt by 1.
	*
	* Fill in fields, remembering maximum advertised
	* window for use in delaying messages about window sizes.
	* If resending a FIN, be sure not to use a new sequence number.
	*/
	if (flags & tcphdr::TH_FIN && tp.t_flags & tcpcb::TF_SENTFIN && tp.snd_nxt == tp.snd_max)
		tp.snd_nxt--;

	/*
	*	Set sequence number field of segment:
	*	The sequence number field of the segment is normally set to snd_nxt, but is set to
	*	snd_max if:
	*	(1) there is no data to send (len equals 0),
	*	(2) neither the SYN flag nor the FIN flag is set, and
	*	(3) the persist timer is not set.
	*
	* If we are doing retransmissions, then snd_nxt will
	* not reflect the first unsent octet.  For ACK only
	* packets, we do not want the sequence number of the
	* retransmitted packet, we want the sequence number
	* of the next unsent octet.  So, if there is no data
	* (and no SYN or FIN), use snd_max instead of snd_nxt
	* when filling in ti_seq.  But if we are in persist
	* state, snd_max might reflect one byte beyond the
	* right edge of the window, so use snd_nxt in that
	* case, since we know we aren't doing a retransmission.
	* (retransmit and persist are mutually exclusive...)
	*/
	ti->ti_seq() =
		(len || (flags & (tcphdr::TH_SYN | tcphdr::TH_FIN)) || tp.t_timer[TCPT_PERSIST]) ?
		htonl(tp.snd_nxt) :
		htonl(tp.snd_max);

	/*
	*	Set acknowledgment field of segment:
	*	The acknowledgment field of the segment is always set to rev _nxt, the next
	*	expected receive sequence number.
	*/
	ti->ti_ack() = htonl(tp.rcv_nxt);

	/*
	*	Set header length If options present:
	*	If TCP options are present (optlen is greater than 0), the options are copied into
	*	the TCP header and the 4-bit header length in the TCP header (th_off) is set to the
	*	fixed size of the TCP header (20 bytes) plus the length of the options, divided by
	*	4. This field is the number of 32-bit words in the TCP header, including options.
	*/
	if (optlen) {
		std::memcpy(&ti[1], opt, optlen);
		ti->ti_off((sizeof(struct tcphdr) + optlen) >> 2);
	}

	/*
	*	The flags field in the TCP header is set from the variable flags.
	*/
	ti->ti_flags() = flags;

	/*
	*	The next part of code fills in more fields in the TCP header and calculates the TCP checksum.
	*
	*	Don't advertise less than one full-sized segment:
	*	Avoidance of the silly window syndrome is performed, this time in calculating the
	*	window size that is advertised to the other end (ti_win). Recall that win was set at the
	*	amount of space in the socket's receive buffer. If win is less than one fourth of the
	*	receive buffer size (so_rcv.sb_hiwat) and less than one full sized segment, the advertised
	*	window will be 0. This is subject to the later test that prevents the window from shrinking.
	*	In other words, when the amount of available space reaches either one-fourth of the receive
	*	buffer size or one full-sized segment, the available space will be advertised.
	*
	* Calculate receive window. Don't shrink window,
	* but avoid silly window syndrome.
	*/
	if (win < static_cast<long>(so.so_rcv.capacity() / 4) &&
		win < static_cast<long>(tp.t_maxseg))
		win = 0;

	/*
	*	Observe upper limit for advertised window on this connection:
	*	If win is larger than the maximum value for this connection, reduce it to its maximum value.
	*/
	if (win > static_cast<long>(TCP_MAXWIN) << tp.rcv_scale)
		win = static_cast<long>(TCP_MAXWIN) << tp.rcv_scale;

	/*
	*	Do not shrink window:
	*	Recall that rcv_adv minus rcv_nxt is the amount of space still available to the sender that
	*	was previously advertised. If win is less than this value, win is set to this value, because
	*	we must not shrink the window. This can happen when the available space is less than one
	*	full-sized segment (hence win was set to 0 at the beginning), but there is room in the
	*	receive buffer for some data. Figure 223 of Volume 1 shows an example of this scenario.
	*/
	if (win < static_cast<long>(tp.rcv_adv - tp.rcv_nxt))
		win = static_cast<long>(tp.rcv_adv - tp.rcv_nxt);

	ti->ti_win() = htons(static_cast<u_short>(win >> tp.rcv_scale));

	/*
	*	Set urgent offset:
	*	If the urgent pointer (snd_up) is greater than snd_nxt, TCP is in urgent mode.
	*	The urgent offset in the TCP header is set to the 16·bit offset of the urgent pointer from
	*	the starting sequence number of the segment, and the URG flag bit is set. TCP sends the
	*	urgent offset and the URG flag regardless of whether the referenced byte of urgent data
	*	is contained in this segment or not.
	*	For example of how the urgent offset is calculated, assuming the  process executes:
	*		send(fd, buf, 3, MSG_OOB);
	*	and the send buffer is empty when this call to send takes place. This shows that Berkeley-
	*	derived systems consider the urgent pointer to point to the first byte of data after the
	*	out-of-band byte. We distinguished between the 32-bit urgent pointer in the data stream
	*	(snd_up), and the 16-bit urgent offset in the TCP header (ti_urp).
	*		Remark:	There is a subtle bug here. The bug occurs when the send buffer Is larger than
	*				65535, regardless of whether the window scale option is in use or not. If the
	*				send buffer is greater than 65535 and is nearly full, and the process sends
	*				out-of-band data, the offset of the urgent pointer from snd_nxt can exceed
	*				65535. But the urgent pointer is a 16 bit unsigned value, and if the
	*				calculated value exceeds 65535, the 16 high-order bits are discarded,
	*				delivering a bogus urgent pointer to the other end.
	*/
	if (tcpcb::SEQ_GT(tp.snd_up, tp.snd_nxt)) {
		ti->ti_urp() = htons(static_cast<u_short>(tp.snd_up - tp.snd_nxt));
		ti->ti_flags() |= tcphdr::TH_URG;
	}
	else

		/*
		*	If TCP is not in urgent mode, the urgent pointer is moved to the left edge of the
		*	window (snd_una).
		*
		* If no urgent pointer to send, then we pull
		* the urgent pointer to the left edge of the send window
		* so that it doesn't drift into the send window on sequence
		* number wraparound.
		*/
		tp.snd_up = tp.snd_una;		/* drag it along */

	/*
	*	The TCP length is stored in the pseudo-header and the TCP checksum is calculated.
	*	All the fields in the TCP header have been filled in, and when the IP and TCP header
	*	template were copied from t_template, the fields in the IP header that are used as
	*	the pseudo-header were initialized.
	*
	* Put TCP length in extended header, and then
	* checksum extended header and data.
	*/
	if (len + optlen)
		ti->ti_len() = htons(static_cast<u_short>(sizeof(struct tcphdr) + optlen + len));

	ti->ti_sum() = inet.in_cksum(&m->data()[it - m->begin()], static_cast<int>(hdrlen + len));

	/*	The next part of tcp_output updates the sequence number if the SYN or FIN flags
	*	are set and initializes the retransmission timer.
	*
	*	Remember starting sequence number:
	*	If TCP is not in the persist state, the starting sequence number is saved in
	*	start seq. This is used later in Figure 26.31 if the segment is timed.
	*
	* In transmit state, time the transmission and arrange for
	* the retransmit.  In persist state, just set snd_max.
	*/
	if (tp.t_force == 0 || tp.t_timer[TCPT_PERSIST] == 0) {
		tcp_seq startseq(tp.snd_nxt);

		/*
		*	Increment snd_nxt:
		*	Since both the SYN and FIN flags take a sequence number, snd_nxt is incremented
		*	if either is set. TCP also remembers that the FIN has been sent, by setting the flag
		*	TF_SENTFIN. snd_nxt is then incremented by the number of bytes of data (len),
		*	which can be 0.
		* Advance snd_nxt over sequence space of this segment.
		*/
		if (flags & (tcphdr::TH_SYN | tcphdr::TH_FIN)) {
			if (flags & tcphdr::TH_SYN)
				tp.snd_nxt++;
			if (flags & tcphdr::TH_FIN) {
				tp.snd_nxt++;
				tp.t_flags |= tcpcb::TF_SENTFIN;
			}
		}

		tp.snd_nxt += len;

		/*
		*	Update and_max:
		*	If the new value of snd_nxt is larger than snd_rnax, this is not a retransmission.
		*	The new value of snd_max is stored.
		*/
		if (tcpcb::SEQ_GT(tp.snd_nxt, tp.snd_max)) {
			tp.snd_max = tp.snd_nxt;

			/*
			*	If a segment is not currently being timed for this connection (t_rtt equals 0), the
			*	timer is started (t_rtt is set to 1) and the starting sequence number of the segment
			*	being timed is saved in t_rtseq. This sequence number is used by tcp_input to
			*	determine when the segment being timed is acknowledged, to update the RIT estimators.
			*	The sample code looked like
			*		if (tp->t_rtt && SEQ_GT(ti->ti_ack, tp->t_rtseq))
			*			tcp_xmit_timer{tp, tp->t_rtt);
			*
			* Time this transmission if not a retransmission and
			* not currently timing anything.
			*/
			if (tp.t_rtt == 0) {
				tp.t_rtt = 1;
				tp.t_rtseq = startseq;
			}
		}

		/*	Set retransmission timer:
		*	If the retransmission timer is not currently set, and if this segment contains data, the
		*	retransmission timer is set to t_rxtcur. Recall that t_rxtcur is set by
		*	tcp_xmit_timer, when an RIT measurement is made. This is an ACK-only segment
		*	if snd_nxt equals snd_una (since len was added to snd_nxt earlier in this figure),
		*	and the retransmission timer is set only for segments containing data.
		*
		* Set retransmit timer if not currently set,
		* and not doing an ack or a keep-alive probe.
		* Initial value for retransmit timer is smoothed
		* round-trip time + 2 * round-trip time variance.
		* Initialize shift counter which is used for backoff
		* of retransmit time.
		*/
		if (tp.t_timer[TCPT_REXMT] == 0 &&
			tp.snd_nxt != tp.snd_una)
		{
			tp.t_timer[TCPT_REXMT] = tp.t_rxtcur;

			/*
			*	If the persist timer is enabled, it is disabled. Either the retransmission timer or the
			*	persist timer can be enabled at any time for a given connection, but not both.
			*/
			if (tp.t_timer[TCPT_PERSIST]) {
				tp.t_timer[TCPT_PERSIST] = 0;
				tp.t_rxtshift = 0;
			}
		}
	}

	/*
	*	Persist state:
	*	The connection is in the persist state since t_force is nonzero and the persist timer
	*	is enabled. (This else clause is associated with the if at the beginning.)
	*	snd_rnax is updated, if necessary. In the persist state, len will be one.
	*/
	else if (tcpcb::SEQ_GT(tp.snd_nxt + len, tp.snd_max))
		tp.snd_max = tp.snd_nxt + len;

	/*
	*	The final part of tcp_output completes the formation of the outgoing segment and calls
	*	ip_output to send the datagram.
	*
		*	Set IP length, TTL, and TOS:
		*	The final three fields in the IP header that must be set by the transport layer are
		*	stored: IP length, TIL, and TOS.
		*		Remark:	The comments XXX are because the latter two fields normally remain constant for
		*				a connection and should be stored in the header template, instead of being
		*				assigned explicitly each time a segment is sent. But these two fields cannot
		*				be stored in the IP header until after the TCP checksum is calculated.
		*
		* Fill in IP length and desired time to live and
		* send to IP level.  There should be a better way
		* to handle ttl and tos; we could keep them in
		* the template, but need a way to checksum without them.
		*/
	reinterpret_cast<struct L3::iphdr*>(ti)->ip_len = static_cast<short>(hdrlen + len);
	reinterpret_cast<struct L3::iphdr*>(ti)->ip_ttl = tp.t_inpcb->inp_ip.ip_ttl;	/* XXX */
	reinterpret_cast<struct L3::iphdr*>(ti)->ip_tos = tp.t_inpcb->inp_ip.ip_tos;	/* XXX */
	reinterpret_cast<struct L3::iphdr*>(ti)->ip_off = 0x4000;

	/*
	*	Pass datagram to IP:
	*	ip_output sends the datagram containing the TCP segment. The socket options
	*	are logically ANDed with SO_DONTROUTE, which means that the only socket option
	*	passed to ip_output is so_oONTROUTE. The only other socket option examined by
	*	ip_output is SO_BROADCAST, so this logical AND turns off the SO_BROADCAST bit, if
	*	set. This means that a process cannot issue a connect to a broadcast address, even if it
	*	sets the SO_BROADCAST socket option.
	*/
	const struct pr_output_args* a = dynamic_cast<const struct pr_output_args*>(&L3_impl::ip_output_args(m, it, tp.t_inpcb->inp_options, &tp.t_inpcb->inp_route, so.so_options & SO_DONTROUTE, nullptr));
	int error(inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*a));
	if (error)
		return out(tp, error);

	/*
	*	Update rev_adv and last_ack_sent:
	*	If the highest sequence number advertised in this segment (rcv_nxt plus win) is
	*	larger than rev_adv, the new value is saved. Recall that rev_adv was used to
	*	determine how much the window had opened since the last segment that was sent,
	*	and to make certain TCP was not shrinking the window.
	*
	* Data sent (as far as we can tell).
	* If this advertises a larger window than any other segment,
	* then remember the size of the advertised window.
	* Any pending ACK has now been sent.
	*/
	if (win > 0 && tcpcb::SEQ_GT(tp.rcv_nxt + win, tp.rcv_adv))
		tp.rcv_adv = tp.rcv_nxt + win;

	/*
	*	The value of the acknowledgment field in the segment is saved in
	*	last_ack_sent. This variable is used by tcp_input with the timestamp option
	*/
	tp.last_ack_sent = tp.rcv_nxt;

	/*
	*	Any pending ACK has been sent, so the TF_ACKNOW and TF_DELACK flags are cleared.
	*/
	tp.t_flags &= ~(tcpcb::TF_ACKNOW | tcpcb::TF_DELACK);

	/*	More data to send?
	*	If the sendalot flag is set, a jump is made back to the label again.
	*	This occurs if the send buffer contains more than one full-sized segment that can be sent
	*	or if a full-sized segment was being sent and TCP options were included that reduced the
	*	amount of data in the segment.
	*/
	if (sendalot)
		return again(tp, idle, so);

	return (0);
}

int L4_TCP::out(tcpcb& tp, int error)
{
	/*
	*	The error ENOBUFS is returned if the interface queue is full or if IP needs to obtain
	*	an mbuf and can't. The function tcp_quench pulls the connection into slow start, by
	*	setting the congestion window to one full-sized segment. Notice that tcp_output still
	*	returns 0 (OK) in this case, instead of the error, even though the datagram was discarded.
	*	This differs from udp_output, which returned the error. The difference is that UDP is
	*	unreliable, so the ENOBUFS error return is the only indication to the process that the
	*	datagram was discarded. TCP, however, will time out (if the segment contains data) and
	*	retransmit the datagram, and it is hoped that there will be space on the interface output
	*	queue or more available mbufs. If the TCP segment doesn't contain data, the other end
	*	will time out when the ACK isn't received and will retransmit the data whose ACK was
	*	discarded.
	*/
	if (error == ENOBUFS) {
		tp.tcp_quench();
		return (0);
	}

	/*
	*	If a route can't be located for the destination, and if the connection has received a
	*	SYN, the error is recorded as a soft error for the connection.
	*	When tcp_output is called by tcp_usrreq as part of a system call by a process
	*	(Chapter 30, the PRU_CONNECT, PRU_SEND, PRU_SENDOOB, and PRU_SHUTDOWN
	*	requests), the process receives the return value from tcp_output. Other functions that
	*	call tcp_output, such as tcp_input and the fast and slow timeout functions, ignore
	*	the return value (because these functions don't return an error to a process).
	*/
	else if ((error == EHOSTUNREACH || error == ENETDOWN) && tp.TCPS_HAVERCVDSYN()) {
		tp.t_softerror = error;
		return (0);
	}
	return (error);
}

void L4_TCP::drop(class inpcb_impl* inp, const int dropsocket)
{
	/*
	* Drop space held by incoming segment and return.
	*
	* destroy temporarily created socket
	*/
	if (dropsocket && inp)
		(void)dynamic_cast<socket*>(inp->inp_socket)->soabort();
	return;
}

void L4_TCP::dropafterack(class tcpcb* tp, const int& dropsocket, const int& tiflags)
{
	/*
	* Generate an ACK dropping incoming segment if it occupies
	* sequence space, where the ACK reflects our state.
	*/
	if (tiflags & tcphdr::TH_RST)
		return drop(tp, dropsocket);
	tp->t_flags |= tcpcb::TF_ACKNOW;
	(void)tcp_output(*tp);
	return;
}

void L4_TCP::dropwithreset(class inpcb_impl* inp, const int& dropsocket, const int& tiflags, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, tcpiphdr* ti)
{
	/*
	* Generate a RST, dropping incoming segment.
	* Make ACK acceptable to originator of segment.
	* Don't bother to respond if destination was broadcast/multicast.
	*/
	if ((tiflags & tcphdr::TH_RST) || IN_MULTICAST(ntohl(ti->ti_dst().s_addr)))
		return drop(inp, dropsocket);

	/*
	*	Sequence number and acknowledgment number of RST segment:
	*	The values of the sequence number field, the acknowledgment field, and the ACK
	*	flag of the RST segment depend on whether the received segment contained an ACK.
	*	Realize that the ACK flag is normally set in all segments except when an initial SYN is
	*	sent (Figure 24.16). The fourth argument to tcp_respond is th.e acknowledgment
	*	field, and the fifth argument is the sequence number.
	*/
	if (tiflags & tcphdr::TH_ACK)
		tcp_respond(tcpcb::intotcpcb(inp),
			ti,
			m,
			it,
			tcp_seq(0),
			ti->ti_ack(),
			tcphdr::TH_RST);
	else {

		/*
		*	Rejecting connections:
		*	If the SYN flag is set, ti_len must be incremented by 1, causing the acknowledgment
		*	field of the RST to be 1 greater than the received sequence number of the SYN.
		*	This code is executed when a SYN arrives for a nonexistent server. When the Internet
		*	PCB is not found in Figure 28.6, a jump is made to dropwithreset. But for the
		*	received RST to be acceptable to the other end, the acknowledgment field must ACK the
		*	SYN (Figure 28.18). Figure 18.14 of Volume 1 contains an example of this type of RST
		*	segment.
		*		Finally note that tcp_respond builds the RST in the first mbuf of the received
		*		chain and releases any remaining mbufs in the chain. When that mbuf finally makes its
		*		way to the device driver, it will be discarded.
		*/
		if (tiflags & tcphdr::TH_SYN)
			ti->ti_len()++;

		tcp_respond(
			tcpcb::intotcpcb(inp),
			ti,
			m,
			it,
			ti->ti_seq() + ti->ti_len(),
			tcp_seq(0),
			tcphdr::TH_RST | tcphdr::TH_ACK);
	}

	/*
	*	Destroy temporarily created socket:
	*	If a temporary socket was created in Figure 28.7 for a listening server, but the code
	*	in Figure 28.16 found the received segment to contain an error, dropsocket will be 1.
	*	If so, that socket is now destroyed.destroy temporarily created socket
	*/
	return drop(inp, dropsocket);
}

void L4_TCP::step6(class tcpcb* tp, int& tiflags, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long& tiwin, int& needoutput)
{
	/*
	* Update window information.
	* Don't look at window if no ACK: TAC's send garbage on first SYN.
	*/
	if ((tiflags & tcphdr::TH_ACK) &&
		(tcpcb::SEQ_LT(tp->snd_wl1, ti->ti_seq()) ||
			tp->snd_wl1 == ti->ti_seq() && (tcpcb::SEQ_LT(tp->snd_wl2, ti->ti_ack()) ||
				tp->snd_wl2 == ti->ti_ack() && tiwin > tp->snd_wnd)))
	{
		/*	Update variables:
		*	The send window is updated and new values of snd_wll and snd_wl2 are
		*	recorded. Additionally, if this advertised window is the largest one TCP has received
		*	from this peer, the new value is recorded in max_sndwnd. This is an attempt to guess
		*	the size of the other end's receive buffer, and it is used in Figure 26.8. needoutput is
		*	set to 1 since the new value of snd_wnd might enable a segment to be sent.
		*/
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = ti->ti_seq();
		tp->snd_wl2 = ti->ti_ack();
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		needoutput = 1;
	}

	/*
	*	Check If URG flag should be processed:
	*	These segments must have the URG flag set, a nonzero urgent offset (ti_urp), and
	*	the connection must not have received a FIN. The macro TCPS_HAVERCVDFIN is true
	*	only for the TIME_ WAIT state, so the URG is processed in any other state. This is contrary
	*	to a comment appearing later in the code stating that the URG flag is ignored in
	*	the CLOSE_ WAIT, CLOSING, LAST_ACK, or TIME_ WAIT states.
	*
	* Process segments with URG.
	*/
	if ((tiflags & tcphdr::TH_URG) && ti->ti_urp() && tp->TCPS_HAVERCVDFIN() == 0) {

		/*
		*	Ignore bogus urgent offsets:
		*	If the urgent offset plus the number of bytes already in the receive buffer exceeds
		*	the maximum size of a socket buffer, the urgent notification is ignored. The urgent offset
		*	is set to 0, the URG flag is cleared, and the rest of the urgent mode processing is skipped.
		*
		* This is a kludge, but if we receive and accept
		* random urgent pointers, we'll crash in
		* soreceive. It's hard to imagine someone
		* actually wanting to send this much urgent data.
		*/
		socket* so(dynamic_cast<socket*>(tp->inp_socket));
		if (ti->ti_urp() + so->so_rcv.size() > netlab::L5_socket::sockbuf::SB_MAX) {
			ti->ti_urp() = 0;			/* XXX */
			tiflags &= ~tcphdr::TH_URG;		/* XXX */
			return dodata(tp, tiflags, ti, m, it, needoutput);			/* XXX */
		}

		/*
		*	If the starting sequence number of the received segment plus the urgent offset
		*	exceeds the current receive urgent pointer, a new urgent pointer has been received. For
		*	example, when the 3-byte segment that was sent in Figure 26.30 arrives at the receiver,
		*	we have the scenario shown in Figure 29.18.
		*
		*		received segment
		*	<---------------------->
		*			tlen = 3
		*		4		5		6
		*		/\
		*		||
		*		rcv_nxt
		*		rcv_up
		*		ti_seq
		*					ti_urp=3
		*				(urgent offset)
		*	Figure 29.18 Receiver side when segment from Figure 26.30 arrives.
		*
		*	Normally the receive urgent pointer (rcv_up) equals rcv_nxt. In this example, since
		*	the if test is true (4 plus 3 is greater than 4), the new value of rev_up is calculated as 7.
		*
		* If this segment advances the known urgent pointer,
		* then mark the data stream.  This should not happen
		* in CLOSE_WAIT, CLOSING, LAST_ACK or TIME_WAIT STATES since
		* a FIN has been received from the remote side.
		* In these states we ignore the URG.
		*
		* According to RFC961 (Assigned Protocols),
		* the urgent pointer points to the last octet
		* of urgent data.  We continue, however,
		* to consider it to indicate the first octet
		* of data past the urgent section as the original
		* spec states (in one of two places).
		*/
		if (tcpcb::SEQ_GT(ti->ti_seq() + ti->ti_urp(), tp->rcv_up)) {

			/*
			*	Calculate receive urgent pointer:
			*	The out-of-band mark in the socket's receive buffer is calculated, taking into
			*	account any data bytes already in the receive buffer (so_rcv.sb_cc). In our example,
			*	assuming there is no data already in the receive buffer, so_oobmark is set to 2: that is,
			*	the byte with the sequence number 6 is considered the out-of-band byte. If this out-of-band
			*	mark is 0, the socket is currently at the out-of-band mark. This happens if the
			*	send system call that sends the out-of-band byte specifies a length of 1, and if the
			*	receive buffer is empty when this segment arrives at the other end. This reiterates that
			*	Berkeley-derived systems consider the urgent pointer to point to the first byte of data
			*	after the out-of-band byte.
			*/
			tp->rcv_up = ti->ti_seq() + ti->ti_urp();
			if ((so->so_oobmark = so->so_rcv.size() + (tp->rcv_up - tp->rcv_nxt) - 1) == 0)
				so->so_state |= socket::SS_RCVATMARK;

			/*
			*	Notify process of TCP's urgent mode:
			*	sohasoutofband notifies the process that out-of-band data has arrived for the
			*	socket. The two flags TCPOOB_HAVEDATA and TCPOOB_HADDATA are cleared. These
			*	two flags are used with the PRU_RCVOOB request in Figure 30.8.
			*/
			//so->sohasoutofband();
			tp->t_oobflags &= ~(tcpcb::TCPOOB_HAVEDATA | tcpcb::TCPOOB_HADDATA);
		}

		/*
		*	Pull out-of-band byte out of normal data stream:
		*	If the urgent offset is less than or equal to the number of bytes in the received segment,
		*	the out-of-band byte is contained in the segment. With TCP's urgent mode it is
		*	possible for the urgent offset to point to a data byte that has not yet been received. If the
		*	SO_OOBINLINE constant is defined (which it always is for Net/3), and if the corresponding
		*	socket option is not enabled, the receiving process wants the out-of-band byte
		*	pulled out of the normal stream of data and placed into the variable t_iobc. This is
		*	done by tcp_pulloutofband, which we cover in the next section.
		*		Notice that the receiving process is notified that the sender has entered urgent
		*	mode, regardless of whether the byte pointed to by the urgent pointer is readable or not.
		*	This is a feature of TCP's urgent mode.
		*
		* Remove out of band data so doesn't get presented to user.
		* This can happen independent of advancing the URG pointer,
		* but if two URG's are pending at once, some out-of-band
		* data may creep in... ick.
		*/
		if (ti->ti_urp() <= ti->ti_len() && (so->so_options & SO_OOBINLINE) == 0)
			tcp_pulloutofband(*so, *ti, m, it);
	}

	/*
	*	Adjust receive urgent pointer If not urgent mode:
	*	When the receiver is not processing an urgent pointer, if rcv_nxt is greater than
	*	the receive urgent pointer, rcv_up is moved to the right and set equal to rcv_nxt.
	*	This keeps the receive urgent pointer at the left edge of the receive window so that the
	*	comparison using SEQ_GT at the beginning of Figure 29.17 will work correctly when an
	*	URG flag is received.
	*		Remark:	If the solution to Exercise 26.6 is implemented, corresponding changes will have to go into Figures
	*				29.16 and 29.17 also.
	*
	* If no out of band data is expected,
	* pull receive urgent pointer along
	* with the receive window.
	*/
	else if (tcpcb::SEQ_GT(tp->rcv_nxt, tp->rcv_up))
		tp->rcv_up = tp->rcv_nxt;

	return dodata(tp, tiflags, ti, m, it, needoutput);
}

void L4_TCP::tcp_pulloutofband(socket& so, const tcpiphdr& ti, std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it)
{
	int cnt(ti.ti_urp() - 1);
	if (cnt >= 0) {

		/*
		*	cp points to the shaded byte with a sequence number of 6. This is placed into the
		*	variable t_iobc, which contains the out-of-band byte. The TCPOOB_HAVEDATA flag is
		*	set and bcopy moves the next 2 bytes (with sequence numbers 7 and 8) left 1 byte, giving
		*	the arrangement shown in Figure 29.21.
		*
		*
		*/
		int m_len(m->end() - it);
		if (m_len > cnt) {
			char* cp(reinterpret_cast<char*>(&m->data()[it - m->begin()]) + cnt);
			tcpcb* tp(tcpcb::sototcpcb(&so));
			tp->t_iobc = *cp;
			tp->t_oobflags |= tcpcb::TCPOOB_HAVEDATA;
			std::memcpy(cp, &cp[1], static_cast<unsigned>(m_len - cnt - 1));
			m->resize(m->size() - 1);
			return;
		}
	}
	throw std::runtime_error("panic(''tcp_pulloutofband''");
}

void L4_TCP::dodata(class tcpcb* tp, int& tiflags, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const int& needoutput) /* XXX */
{
	socket* so(dynamic_cast<socket*>(tp->inp_socket));

	/*
	* Process the segment text, merging it into the TCP sequencing queue,
	* and arranging for acknowledgment of receipt if necessary.
	* This process logically involves adjusting tp->rcv_wnd as data
	* is presented to the user (this happens in tcp_usrreq.c,
	* case PRU_RCVD).  If a FIN has already been received on this
	* connection then we just ignore the text.
	*/
	if ((ti->ti_len() || (tiflags & tcphdr::TH_FIN)) && tp->TCPS_HAVERCVDFIN() == 0)
		TCP_REASS(tp, ti, m, it, so, tiflags);

	/*
	*	If the length is 0 and the FIN flag is not set, or if a FIN has already been received for
	*	the connection, the received mbuf chain is discarded and the FIN flag is cleared.
	*/
	else
		tiflags &= ~tcphdr::TH_FIN;

	/*
	*	Process first FIN received on connection:
	*	If the FIN flag is set and this is the first FIN received for this connection,
	*	socantrcvmore marks the socket as write-only, TF ACKNOW is set to acknowledge the
	*	FIN immediately (i.e., it is not delayed), and rcv_nxt steps over the FIN in the
	*	sequence space.
	*
	* If FIN is received ACK the FIN and let the user know
	* that the connection is closing.
	*/
	if (tiflags & tcphdr::TH_FIN) {
		if (tp->TCPS_HAVERCVDFIN() == 0) {
			so->socantrcvmore();
			tp->t_flags |= tcpcb::TF_ACKNOW;
			tp->rcv_nxt++;
		}

		/*
		*	The remainder of FIN processing is handled by a switch that depends on the connection
		*	state. Notice that the FIN is not processed in the CLOSED, LISTEN, or
		*	SYN_SENT states, since in these three states a SYN has not been received to synchronize
		*	the received sequence number, making it impossible to validate the sequence number of
		*	the FIN. A FIN is also ignored in the CLOSING, CLOSE_WAIT, and LAST_ACK states,
		*	because in these three states the FIN is a duplicate.
		*/
		switch (tp->t_state) {

			/*
			 *	SYN_RCVD or ESTABLISHED states:
			*	From either the ESTABLISHED or SYN_RCVD states, the CLOSE_WAIT state is entered.
			*		Remark:	The receipt of a FIN in the SYN_RCVD state is unusual, but legal. It is not shown in Figure
			*				24.15. It means a socket is in the LISTEN state when a segment containing a SYN and a
			*				FIN is received. Alternatively, a SYN is received for a listening socket, moving the connection
			*				to the SYN_RCVD state but before the ACK is received a FIN is received. (We know the segment
			*				does not contain a valid ACK, because if it did the code in Figure 29.2 would have
			*				moved the connection to the ESTABLISHED state.)
			*
			* In SYN_RECEIVED and ESTABLISHED STATES
			* enter the CLOSE_WAIT state.
			*/
		case tcpcb::TCPS_SYN_RECEIVED:
		case tcpcb::TCPS_ESTABLISHED:
			tp->t_state = tcpcb::TCPS_CLOSE_WAIT;
			break;

			/*
			*	FIN_WAIT_1 state:
			*	Since ACK processing is already complete for this segment, if the connection is in
			*	the FIN_WAIT_1 state when the FIN is processed, it means a simultaneous close is taking
			*	place-the two FINs from each end have passed in the network. The connection
			*	enters the CLOSING state.
			*
			* If still in FIN_WAIT_1 STATE FIN has not been acked so
			* enter the CLOSING state.
			*/
		case tcpcb::TCPS_FIN_WAIT_1:
			tp->t_state = tcpcb::TCPS_CLOSING;
			break;

			/*	FIN_WAIT_2 state:
			*	The receipt of the FIN moves the connection into the TIME_WAIT state. When a
			*	segment containing a FIN and an ACK is received in the FIN_ WAIT 1 state (the typical
			*	scenario), although Figure 24.15 shows the transition directly from the FIN_WAIT_1
			*	state to the TIME_WAIT state, the ACK is processed in Figure 29.11, moving the connection
			*	to the FIN_WAIT_2 state. The FIN processing here moves the connection into the
			*	TIME_WAIT state. Because the ACK is processed before the FIN, the FIN_WAIT_2 state
			*	is always passed through, albeit momentarily.
			*
			* In FIN_WAIT_2 state enter the TIME_WAIT state,
			* starting the time-wait timer, turning off the other
			* standard timers.
			*/
		case tcpcb::TCPS_FIN_WAIT_2:
			tp->t_state = tcpcb::TCPS_TIME_WAIT;

			/*
			*	Start TIME_WAIT Timer:
			*	Any pending TCP timer is turned off and the TIME_WAIT timer is started with a
			*	value of twice the MSL. (If the received segment contained a FIN and an ACK, Figure
			*	29.11 started the FIN_WAIT_2 timer.) The socket is disconnected.
			*/
			tp->tcp_canceltimers();
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			so->soisdisconnected();
			break;

			/*
			*	TIME_WAIT state:
			*	If a FIN arrives in the TIME_WAIT state, it is a duplicate, and similar to Figure
			*	29.14, the TIME_WAIT timer is restarted with a value of twice the MSL.
			*
			* In TIME_WAIT state restart the 2 MSL time_wait timer.
			*/
		case tcpcb::TCPS_TIME_WAIT:
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			break;
		}
	}

	/*
	*	Call tcp_output
	*	If either the needoutput flag was set (Figures 29.6 and 29.15) or if an immediate
	*	ACK is required, tcp_output is called.
	*
	* Return any desired output.
	*/
	if (needoutput || (tp->t_flags & tcpcb::TF_ACKNOW))
		(void)tcp_output(*tp);
	return;
}

void L4_TCP::TCP_REASS(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, socket* so, int& flags)
{
	if (ti->ti_seq() == tp->rcv_nxt &&
		tp->seg_next == reinterpret_cast<struct tcpiphdr*>(tp) &&
		tp->t_state == tcpcb::TCPS_ESTABLISHED)
	{
		tp->t_flags |= tcpcb::TF_DELACK;
		tp->rcv_nxt += ti->ti_len();
		flags = ti->ti_flags() & tcphdr::TH_FIN;
		//std::lock_guard<std::mutex> lock(so->so_rcv.sb_mutex);
		auto view = boost::make_iterator_range(it, it + ti->ti_len());
		so->so_rcv.sbappends(view);
		so->sorwakeup();
	}
	else {
		flags = tcp_reass(tp, ti, m, it);
		tp->t_flags |= tcpcb::TF_ACKNOW;
	}
}

int L4_TCP::tcp_reass(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it)
{
	/*
	*	We'll see that tcp_input calls tcp_reass with a null ti pointer when a SYN is
	*	acknowledged (Figures 28.20 and 29.2). This means the connection is now established,
	*	and any data that might have arrived with the SYN (which tcp_reass had to queue
	*	earlier) can now be passed to the application. Data that arrives with a SYN cannot be
	*	passed to the process until the connection is established. The label present is in Figure
	*	27.23.
	*
	* Call with ti==0 after become established to
	* force pre-ESTABLISHED data up to user socket.
	*/
	if (ti == nullptr)
		return present(tp, ti, m, it);
#ifndef NETLAB_NO_REASS_MBUF
	/*
	*	Go through the list of segments for this connection, starting at seg_next, to find
	*	the first one with a sequence number that is greater than the received sequence number
	*	(ti_seq). Note that the if statement is the entire body of the for loop.
	*
	* Find a segment which begins after this one does.
	*/
	struct tcpiphdr* q;
	for (q = tp->seg_next; q->ti_next() != nullptr/*q != reinterpret_cast<struct tcpiphdr *>(tp)*/; q = q->ti_next())
		if (tcpcb::SEQ_GT(q->ti_seq(), ti->ti_seq()))
			break;

	/*
	*	If there is a segment before the one pointed to by q, that segment may overlap the
	*	new segment. The pointer q is moved to the previous segment on the list (the one with
	*	bytes 4-8 in Figure 27.18) and the number of bytes of overlap is calculated and stored
	*	in i:
	*			i	= q->ti_seq + q->ti_len - ti->ti_seq;
	*				= 4 + 5 - 7
	*				= 2
	*
	*	If i is greater than 0, there is overlap, as we have in our example. If the number of bytes
	*	of overlap in the previous segment on the list (i) is greater than or equal to the size of
	*	the new segment, then all the data bytes in the new segment are already contained in
	*	the previous segment on the list. In this case the duplicate segment is discarded.
	*
	* If there is a preceding segment, it may provide some of
	* our data already.  If so, drop the data from the incoming
	* segment.  If it provides all of our data, drop us.
	*/
	if (q->ti_prev() != reinterpret_cast<struct tcpiphdr*>(tp)) {
		q = q->ti_prev();
		/* conversion to int (in i) handles seq wraparound */
		int i(q->ti_seq() + q->ti_len() - ti->ti_seq());
		if (i > 0) {
			if (i >= ti->ti_len())
				return (0);

			/*
			*	If there is only partial overlap (as there is in Figure 27.18), m_adj discards i bytes of
			*	data from the beginning of the new segment. The sequence number and length of the
			*	new segment arc updated accordingly. q is moved to the next segment on the list. Figure
			*	27.20 shows our example at this point.
			*/
			std::move(it + i, m->end(), it);
			m->resize(m->size() - i);
			ti->ti_len() -= i;
			ti->ti_seq() += i;
		}
		q = q->ti_next();
	}

	/*
	*	The address of the mbuf m is stored in the TCP header, over the source and destination
	*	TCP ports. We mentioned earlier in this section that this provides a back pointer
	*	from the TCP header to the mbuf, in case the TCP header is stored in a duster, meaning
	*	that the macro dtom won't work. The macro REASS_MBUF is
	*		#define REASS_MBUF(ti) {*(struct mbuf **)&((ti)->ti_t)}
	*	ti_t is the tcphdr structure (Figure 24.12) and the first two members of the structure
	*	are the two 16-bit port numbers. The comment XXX in Figure 27.19 is because this hack
	*	assumes that a pointer fits in the 32 bits occupied by the two port numbers.
	*/
	ti->REASS_MBUF() = m;		/* XXX */

	/*
	*	The third part of tcp_reass is shown in Figure 27.21. It removes any overlap from
	*	the next segment in the queue.
	*	If there is another segment on the list, the number of bytes of overlap between the
	*	new segment and that segment is calculated in i. In our example we have
	*			i	= 9 + 2 - 10
	*				= 1
	*	since byte number 10 overlaps the two segments.
	*	Depending on the value of i, one of three conditions exists:
	*		1.	If i is less than or equal to 0, there is no overlap.
	*		2.	If i is less than the number of bytes in the next segment (q->ti_len), there is
	*			partial overlap and rn_adj removes the first i bytes from the next segment on
	*			the list.
	*		3.	If i is greater than or equal to the number of bytes in the next segment, there is
	*			complete overlap and that next segment on the list is deleted.
	*
	* While we overlap succeeding segments trim them or,
	* if they are completely covered, dequeue them.
	*/
	while (q != nullptr/*reinterpret_cast<struct tcpiphdr *>(tp)*/) {
		int i((ti->ti_seq() + ti->ti_len()) - q->ti_seq());
		if (i <= 0)
			break;
		if (i < q->ti_len()) {
			q->ti_seq() += i;
			q->ti_len() -= i;
			std::shared_ptr<std::vector<byte>> adj(q->REASS_MBUF());
			std::move(adj->begin() + i, adj->end(), adj->begin());
			m->resize(m->size() - i);
			break;
		}
		q = q->ti_next();
		m = q->ti_prev()->REASS_MBUF();
		q->ti_prev()->remque();
	}


	/*
	*	The new segment is inserted into the reassembly list for this connection by insque.
	*	Figure 27.22 shows the state of our example at this point.
	*
	* Stick new segment in its place.
	*/
	q->ti_prev()->insque(*ti);
#endif
	return present(tp, ti, m, it);
}

int L4_TCP::present(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it)
{
	if (tp->TCPS_HAVERCVDSYN() == false ||
		(ti = tp->seg_next) == reinterpret_cast<struct tcpiphdr*>(tp) ||
		ti->ti_seq() != tp->rcv_nxt ||
		(tp->t_state == tcpcb::TCPS_SYN_RECEIVED && ti->ti_len()))
		return (0);

	int flags(0);
#ifndef NETLAB_NO_REASS_MBUF
	socket* so(dynamic_cast<socket*>(tp->t_inpcb->inp_socket));
	do {
		tp->rcv_nxt += ti->ti_len();
		flags = ti->ti_flags() & tcphdr::TH_FIN;
		ti->remque();
		m = ti->REASS_MBUF();
		ti = ti->ti_next();
		if (!(so->so_state & socket::SS_CANTRCVMORE))
			so->so_rcv.sbappend(m->begin(), m->end());
	} while (ti != reinterpret_cast<struct tcpiphdr*>(tp) && ti->ti_seq() == tp->rcv_nxt);
	so->sorwakeup();
#endif
	return (flags);
}

void  L4_TCP::tcp_respond(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const tcp_seq& ack, const tcp_seq& seq, const int& flags)
{
	int win(tp ? dynamic_cast<socket*>(tp->t_inpcb->inp_socket)->so_rcv.sbspace() : 0),
		tlen;
	struct L3::route* ro(tp ? &tp->t_inpcb->inp_route : nullptr);
	if (m) {
		m.reset(new std::vector<byte>(sizeof(struct tcpiphdr) + sizeof(struct L2::ether_header)));
		std::copy(
			reinterpret_cast<byte*>(ti),
			reinterpret_cast<byte*>(ti) + sizeof(struct tcpiphdr),
			it = m->begin() + sizeof(struct L2::ether_header)
		);

		ti = reinterpret_cast<struct tcpiphdr*>(&m->data()[it - m->begin()]);
		tlen = 0;
		std::swap(ti->ti_dst(), ti->ti_src());
		std::swap(ti->ti_dport(), ti->ti_sport());
	}
	else
		return;

	ti->ti_len() = htons(static_cast<u_short>(sizeof(struct tcphdr) + tlen));

	tlen += sizeof(struct tcpiphdr);

	ti->ti_next(nullptr);
	ti->ti_prev(nullptr);
	ti->ti_x1() = 0;

	ti->ti_seq() = htonl(seq);
	ti->ti_ack() = htonl(ack);

	ti->ti_x2(0);
	ti->ti_off(sizeof(struct tcphdr) >> 2);
	ti->ti_flags() = flags;

	ti->ti_win() =
		(tp ?
			htons(static_cast<u_short>(win >> tp->rcv_scale)) :
			htons(static_cast<u_short>(win)));

	ti->ti_urp() = 0;
	ti->ti_sum() = 0;

	ti->ti_sum() = inet.in_cksum(&m->data()[it - m->begin()], tlen);

	reinterpret_cast<struct L3::iphdr*>(ti)->ip_len = tlen;
	reinterpret_cast<struct L3::iphdr*>(ti)->ip_ttl = L3_impl::IPDEFTTL;

#ifndef NETLAB_NO_TCP_RESPOND
	(void)inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*dynamic_cast<const struct pr_output_args*>(
		&L3_impl::ip_output_args(
			m,
			it,
			std::shared_ptr<std::vector<byte>>(nullptr),
			ro,
			0,
			nullptr)
		));
#endif
}

void L4_TCP::tcp_dooptions(tcpcb& tp, u_char* cp, int cnt, tcpiphdr& ti, int& ts_present, u_long& ts_val, u_long& ts_ecr)
{
	u_short mss;
	int opt, optlen;

	/*
	*	Fetch option type and length:
	*	The options are scanned and an EOL (end-of-options) terminates the processing,
	*	causing the function to return. The length of a NOP is set to l, since this option is not
	*	followed by a length byte (Figure 26.16). The NOP will be ignored via the default in
	*	the switch statement.
	*/
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		if ((opt = cp[0]) == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;

		/*
		*	All other options have a length byte that is stored in optlen.
		*	Any new options that are not understood by this implementation of TCP are also
		*	ignored. This occurs because:
		*		1.	Any new options defined in the future will have an option length (NOP and
		*			EOL are the only two without a length), and the for loop skips optlen bytes
		*			each time around the loop.
		*		2.	The default in the switch statement ignores unknown options.
		*/
		else if ((optlen = cp[1]) <= 0)
			break;

		/*
		*	The final part of tcp_dooptions handles the MSS, window
		*	scale, and timestamp options.
		*/
		switch (opt) {

		default:
			continue;

			/*
			*	MSS option:
			*	If the length is not 4 (TCPOLEN_MAXSEG), or the segment does not have the SYN
			*	flag set, the option is ignored. Otherwise the 2 MSS bytes are copied into a local variable,
			*	converted to host byte order, and processed by tcp_mss. This has the side effect
			*	of setting the variable t_rnaxseg in the control block, the maximum number of bytes
			*	that can be sent in a segment to the other end.
			*/
		case TCPOPT_MAXSEG:
			if ((optlen != TCPOLEN_MAXSEG) || !(ti.ti_flags() & tcphdr::TH_SYN))
				continue;

			std::memcpy(&mss, &cp[2], sizeof(mss));
			(void)tcp_mss(tp, mss = ntohs(mss));	/* sets t_maxseg */

			break;

			/*
			*	Window scale option
			*	If the length is not 3 (TCPOLEN_WINDOW), or the segment does not have the SYN
			*	flag set, the option is ignored. Net/3 remembers that it received a window scale
			*	request, and the scale factor is saved in requested_s_scale. Since only 1 byte is referenced
			*	by cp[2], there can't be alignment problems. When the ESTABLISHED state is
			*	entered, if both ends requested window scaling, it is enabled.
			*/
		case TCPOPT_WINDOW:
			if ((optlen != TCPOLEN_WINDOW) || !(ti.ti_flags() & tcphdr::TH_SYN))
				continue;

			tp.t_flags |= tcpcb::TF_RCVD_SCALE;
			tp.requested_s_scale = std::min(cp[2], static_cast<u_char>(TCP_MAX_WINSHIFT));

			break;

			/*
			*	Timestamp option:
			*	If the length is not 10 (TCPOLEN_TIMESTAMP), the segment is ignored. Otherwise
			*	the flag pointed to by ts_present is set to 1, and the two timestamps are saved in the
			*	variables pointed to by ts_val and ts_ecr. If the received segment contains the SYN
			*	flag, Net/3 remembers that a timestamp request was received. ts_recent. is set to the
			*	received timestamp and ts_recent_age is set to tcp_now, the counter of the number
			*	of 500-ms clock ticks since the system was initialized.
			*/
		case TCPOPT_TIMESTAMP:
			if (optlen != TCPOLEN_TIMESTAMP)
				continue;

			ts_present = 1;
			std::memcpy(&ts_val, &cp[2], sizeof(ts_val));
			ts_val = ntohl(ts_val);

			std::memcpy(&ts_ecr, &cp[6], sizeof(ts_ecr));
			ts_ecr = ntohl(ts_ecr);

			/*
			* A timestamp received in a SYN makes
			* it ok to send timestamp requests and replies.
			*/
			if (ti.ti_flags() & tcphdr::TH_SYN) {
				tp.t_flags |= tcpcb::TF_RCVD_TSTMP;
				tp.ts_recent = ts_val;
				tp.ts_recent_age = tcp_now;
			}
			break;
		}
	}
}

int L4_TCP::tcp_mss(class tcpcb& tp, u_int offer)
{

	/*
	 *	Acquire a route If necessary:
	 *	If the socket does not have a cached route, rtalloc acquires one. The interface
	 *	pointer associated wi th the outgoing route is saved in if p. Knowing the outgoing
	 *	interface is important, since its associated MTU can affect the MSS announced by TCP.
	 *	If a route is not acquired, the default of 512 (tcp_rossdfl t) is returned immediately.
	 */
	class inpcb* inp(tp.t_inpcb);


	struct L3::route& ro(inp->inp_route);
	struct L3::rtentry* rt(ro.ro_rt);
	if (rt == nullptr) {
		/* No route yet, so try to acquire one */
		if (inp->inp_faddr().s_addr != INADDR_ANY) {
			ro.ro_dst.sa_family = AF_INET;
			reinterpret_cast<struct sockaddr_in*>(&ro.ro_dst)->sin_addr = inp->inp_faddr();
			ro.rtalloc(&inet);
		}
		if ((rt = ro.ro_rt) == nullptr)
			return (tcp_mssdflt);
	}

	class inet_os* ifp(rt->rt_ifp);
	socket* so(dynamic_cast<socket*>(inp->inp_socket));

	/*
	 *	The next part of tcp_ross, shown in Figure 27.8, checks whether the route has metrics
	 *	associated with it; if so, the variables t_rttmin, t_srtt, and t_rttvar can be
	 *	initialized from the metrics.
	 *
	 *	Initialize smoothed RTT estimator:
	 *	If there are no RTT measurements yet for the connection (t_srtt is 0) and
	 *	rmx_rt t is nonzero, the latter initializes the smoothed RTT estimator t_srt t. If the
	 *	RTV_RTT bit in the routing metric lock flag is set, it indicates that rmx_rt t should also
	 *	be used to initialize the minimum RTT for this connection (t_rttmin). We saw that
	 *	tcp_newtcpcb initializes t_rttmin to 2 ticks.
	 *		rmx_rt t (in units of microseconds) is converted to t_srt t (in units of ticks x 8).
	 *	This is the reverse of the conversion done in Figure 27.4. Notice that t_rttrnin is set to
	 *	one-eighth the value of t_srtt, since the former is not divided by the scale factor
	 *	TCP_RTT SCALE.
	 *
	* While we're here, check if there's an initial rtt
	* or rttvar. Convert from the route-table units
	* to scaled multiples of the slow timeout timer.
	*/
	if (tp.t_srtt == 0 && rt->rt_rmx.rmx_rtt) {
		int rtt(rt->rt_rmx.rmx_rtt);

		/*!
			\bug the lock bit for MTU indicates that the value is also a minimum value; this is subject to time.
		 */
		if (rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTT)
			tp.t_rttmin = rtt / (L3::rtentry::RTM_RTTUNIT / PR_SLOWHZ);
		tp.t_srtt = rtt / (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE));

		/*
		 *	Initialize smoothed mean deviation estimator:
		 *	If the stored value of rmx_rttvar is nonzero, it is converted from units of
		 *	microseconds into ticks x 4 and stored in t_rttvar. But if the value is 0, t_rttvar is
		 *	set to t_rtt, that is, the variation is set to the mean. This defaults the variation to ± 1
		 *	RTT. Since the units of the former are ticks x 4 and the units of the latter are ticks x 8,
		 *	the value of t_srt t is converted accordingly.
		 */
		if (rt->rt_rmx.rmx_rttvar)
			tp.t_rttvar = static_cast<short>(rt->rt_rmx.rmx_rttvar / (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE)));
		else
			/* default variation is +- 1 rtt */
			tp.t_rttvar = tp.t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;

		/*
		 *	calculate initial RTO
		 *	The current RTO is calculated and stored in t_rxtcur, using the unscaled equation
		 *				RTO = srtt + 2 * rttvar
		 *	A multiplier of 2, instead of 4, is used to calculate the first RTO. This is the same equation
		 *	that was used in Figure 25.21. Substituting the scaling relationships we get
		 *				RTO = t_srtt + 2 * t_rttvar = (t_srtt / 4 + t_rttvar) / 2
		 *	which is the second argument to TCPT_RANGESET.
		 */
		TCPT_RANGESET(
			tp.t_rxtcur,
			((tp.t_srtt >> 2) + tp.t_rttvar) >> 1,
			tp.t_rttmin,
			TCPTV_REXMTMAX);
	}

	/*
	 *	The next part of tcp_mss, shown in Figure 27.9, calculates the MSS.
	 *	Use MSS from routing table MTU:
	 *	If the MTU is set in the routing table, mss is set to that value. Otherwise mss starts
	 *	at the value of the outgoing interface MTU minus 40 (the default size of the IP and TCP
	 *	headers). For an Ethernet, mss would start at 1460.
	 *
	* if there's an mtu associated with the route, use it
	*/
	int mss(
		rt->rt_rmx.rmx_mtu ?
		rt->rt_rmx.rmx_mtu - sizeof(struct tcpiphdr) :
		(ifp ?
			ifp->nic()->if_mtu() - sizeof(struct tcpiphdr) :
			inet.nic()->if_mtu() - sizeof(struct tcpiphdr)));

	/*
	*	Round MSS down to multiple of MCLBYTBS
	*	The goal of these lines of code is to reduce the value of mss to the next-lower multiple
	*	of the mbuf cluster size, if mss exceeds MCLBYTES. If the value of MCLBYTES (typically
	*	1024 or 2048) logically ANDed with the value minus 1 equals 0, then MCLBYTES is
	*	a power of 2. For example, 1024 (Ox400) logically ANDed with 1023 (Ox3ff) is 0.
	*		The value of mss is reduced to the next-lower multiple of MCLBYTES by clearing the
	*	appropriate number of low-order bits: if the cluster size is 1024, logically ANDing mss
	*	with the one's complement of 1023 (Oxfffffc00) clears the low-order 10 bits. For an
	*	Ethernet, this reduces mss from 1460 to 1024. If the duster size is 2048, logically ANDing
	*	mss with the one's complement of 2047 (Oxffff8000) clears the low-order 11 bits.
	*	For a token ring with an MTU of 4464, this reduces the value of mss from 4424 to 4096.
	*	If MCLBYTES is not a power of 2, the rounding down to the next-lower multiple of
	*	MCLBYTES is done with an integer division followed by a multiplication.
	*/
#define	MCLBYTES	2048		/* large enough for ether MTU */
#if (MCLBYTES & (MCLBYTES - 1)) == 0
	if (mss > MCLBYTES)
		mss &= ~(MCLBYTES - 1);
#else
	if (mss > MCLBYTES)
		mss /= MCLBYTES * MCLBYTES;
#endif

	/*
	*	Check If destination local or nonlocal
	*	If the foreign IP address is not local (in_localaddr returns 0), and if mss is
	*	greater than 512 (tcp_mssdflt), it is set to 512.
	*		Remark:	Whether an IP address is "local" or not depends on the value of the global
	*				subnetsarelocal, which is initialized from the symbol SUBNETSARELOCAL when the kernel
	*				is compiled. The default value is 1, meaning that an IP address with the same network ID
	*				as one of the host's interfaces is considered local. If the value is 0, an IP address must have the
	*				same network ID and the same subnet ID as one of the host's interfaces to be considered local.
	*
	*				This minimization for nonlocal hosts is an attempt to avoid fragmentation across wide-area
	*				networks. It is a historical artifact from the ARPANET when the MTU across most WAN links
	*				was 1006. As discussed in Section 11.7 of Volume 1, most WANs today support an MTU of
	*				1500 or greater. See also the discussion of the path MTU discovery feature (RFC 1191 [Mogul
	*				and Deering 1990]), in Section 24.2 of Volume 1. Net/3 does not support path MTU discovery.
	*/
	if (!inet.nic()->in_localaddr(inp->inp_faddr()))
		mss = std::min(mss, tcp_mssdflt);

	/*
	 *	The final part of tcp_mss is shown in Figure 27.10:
	 *	Other end's MSS is upper bound:
	 *	The argument of fer is nonzero when this function is called from tcp_inpuc, and
	 *	its value is the MSS advertised by the other end. If the value of mss is greater than the
	 *	value advertised by the other end, it is set to the value of offer. For example, if the
	 *	function calculates an mss of 1024 but the advertised value from the other end is 512,
	 *	mss must be set to 512. Conversely, if mss is calculated as 536 (say the outgoing MTU is
	 *	576) and the other end advertises an MSS of 1460, TCP will use 536. TCP can always
	 *	use a value less than the advertised MSS, but it can't exceed the advertised value. The
	 *	argument offer is 0 when this function is called by tcp_output to send an MSS
	 *	option. The value of mss is also lower bounded by 32.
	 *
	* The current mss, t_maxseg, is initialized to the default value.
	* If we compute a smaller value, reduce the current mss.
	* If we compute a larger value, return it for use in sending
	* a max seg size option, but don't store it for use
	* unless we received an offer at least that large from peer.
	* However, do not accept offers under 32 bytes.
	*/
	mss = offer ? std::min(mss, static_cast<int>(offer)) : std::max(mss, 32); /* sanity */

	/*
	 *	If the value of mss has decreased from the default set by tcp_newtcpcb in the
	 *	variable t_maxseg (512), or if TCP is processing a received MSS option (offer is
	 *	nonzero), the following steps occur:
	 *		1.	First, if the value of rmx_sendpipe has been stored for the route,
	 *			its value will be used as the send buffer high-water mark (Figure 16.4).
	 *		2.	If the buffer size is less than mss, the smaller value is used. This should never
	 *			happen unless the application explicitly sets the send buffer size to a small value, or the
	 *			administrator sets rmx_sendpipe to a small value, since the high-water mark of the
	 *			send buffer defaults to 8192, larger than most values for the MSS.
	 */
	if (mss < tp.t_maxseg || offer != 0) {

		/*
		* If there's a pipesize, change the socket buffer
		* to that size.  Make the socket buffers an integral
		* number of mss units; if the mss is larger than
		* the socket buffer, decrease the mss.
		*/
		u_long bufsize(rt->rt_rmx.rmx_sendpipe);
		if (bufsize == 0)
			bufsize = so->so_snd.capacity();
		if (static_cast<int>(bufsize) < mss)
			mss = bufsize;
		else {
			/*
			 *	Round buffer sizes to multiple of MSS:
			 *	The send buffer size is rounded up to the next integral multiple of the MSS,
			 *	bounded by the value of sb_max (262,144 on Net/3, which is 256 * 1024). The socket's
			 *	high-water mark is set by sbreserve. For example, the default high-water mark is
			 *	8192, but for a local TCP connection on an Ethernet with a cluster size of 2048 (i.e., an
			 *	MSS of 1460) this code increases the high-water mark to 8760 (which is 6x 1460). But
			 *	for a nonlocal connection with an MSS of 512, the high-water mark is left at 8192.
			 */
			if ((bufsize = roundup(bufsize, static_cast<u_long>(mss))) > netlab::L5_socket::sockbuf::SB_MAX)
				bufsize = netlab::L5_socket::sockbuf::SB_MAX;
			(void)so->so_snd.sbreserve(bufsize);
		}

		/*
		 *	The value of t_maxseg is set, either because it decreased from the default (512) or
		 *	because an MSS option was received from the other end.
		 */
		tp.t_maxseg = mss;

		/*
		 *	The same logic just applied to the send buffer is also applied to the receive buffer.
		 */
		if ((bufsize = rt->rt_rmx.rmx_recvpipe) == 0)
			bufsize = so->so_rcv.capacity();
		if (static_cast<int>(bufsize) > mss) {
			if ((bufsize = roundup(bufsize, static_cast<u_long>(mss))) > netlab::L5_socket::sockbuf::SB_MAX)
				bufsize = netlab::L5_socket::sockbuf::SB_MAX;
			(void)so->so_rcv.sbreserve(bufsize);
		}
	}

	/*
	 *	Initialize congestion window and slow start threshold:
	 *	The value of the congestion window, snd_cwnd, is set to one segment. If the
	 *	rmx_ssthresh value in the routing table is nonzero, the slow start threshold
	 *	(snd_ssthresh) is set to that value, but the value must not be less than two segments.
	 */
	tp.log_snd_cwnd(tp.snd_cwnd = mss);
	if (rt->rt_rmx.rmx_ssthresh)
		/*
		* There's some sort of gateway or interface
		* buffer limit on the path.  Use this to set
		* the slow start threshhold, but set the
		* threshold to no less than 2*mss.
		*/
		tp.snd_ssthresh = std::max(2 * mss, static_cast<int>(rt->rt_rmx.rmx_ssthresh));

	/*
	 *	The value of mss is returned by the function. tcp_input ignores this value in Figure
	 *	28.10 (since it received an MSS from the other end), but tcp_output sends this
	 *	value as the announced MSS in Figure 26.23.
	 */
	return (mss);
}

void L4_TCP::trimthenstep6(class tcpcb* tp, int& tiflags, tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long& tiwin, int& needoutput)
{
	/*
	*	The sequence number of the segment is incremented by 1 to account for the SYN. If
	*	there is any data in the segment, ti.ti_seq() now contains the starting sequence number of
	*	the first byte of data.
	*
	* Advance ti->ti_seq to correspond to first data byte.
	* If data, trim to stay within window,
	* dropping FIN if necessary.
	*/
	ti->ti_seq()++;

	/*
	*	Drop any received data that follows receive window:
	*	tlen is the number of data bytes in the segment. If it is greater than the receive
	*	window, the excess data (ti_len minus rcv_wnd) is dropped. The data to be trimmed
	*	from the end of the buf (Figure 2.20). tlen is updated to be the new amount of data
	*	in the mbuf chain and in case the FIN flag was set, it is cleared.
	*	This is because the FIN would follow the final data byte, which was just discarded
	*	because it was outside the receive window.
	*		Remark:	If too much data is received with a SYN, and if the SYN is in response
	*				to an active open the other end received TCP's SYN, which contained a
	*				window advertisement. This means the other end ignored the advertised
	*				window and is exhibiting unsocial behavior. But if too much data
	*				accompanies a SYN performing an active open, the other end has not
	*				received a window advertisement, so it has to guess how much data can
	*				accompany its SYN.
	*/
	if (static_cast<u_long>(ti->ti_len()) > tp->rcv_wnd) {
		ti->ti_len() = static_cast<short>(tp->rcv_wnd);
		tiflags &= ~tcphdr::TH_FIN;
	}

	/*
	*	Force update of window variables:
	*	snd_wl1 is set the received sequence number minus 1. We'll see in Figure 29.15
	*	that this causes the three window update variables, snd_wnd, snd_wll, and snd_wl2,
	*	to be updated. The receive urgent pointer (rcv_up) is set to the received sequence
	*	number. A jump is made to step6, which refers to a step in RFC 793, and we cover this
	*	in Figure 29.15.
	*/
	tp->snd_wl1 = ti->ti_seq() - 1;
	tp->rcv_up = ti->ti_seq();

	return step6(tp, tiflags, ti, m, it, tiwin, needoutput);
}



inline void	L4_TCP::TCP_ISSINCR(const int div) { tcp_iss += (250 * 1024) / div; }

void L4_TCP::print(struct tcpiphdr& tcpip, uint16_t tcp_checksum, std::string intro, std::ostream& str) const
{
	std::swap(tcp_checksum, tcpip.ti_sum());
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << intro << std::endl << tcpip << std::endl;
	std::swap(tcp_checksum, tcpip.ti_sum());
}



void L4_TCP::print(struct tcphdr& tcp, uint16_t tcp_checksum, std::string intro, std::ostream& str) const
{
	std::swap(tcp_checksum, tcp.th_sum);
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << intro << std::endl << tcp << std::endl;
	std::swap(tcp_checksum, tcp.th_sum);
}

void L4_TCP::tcp_congestion_conrol_handler(tcpcb* tp)
{
	u_int cw(tp->snd_cwnd);
	float incr(tp->t_maxseg);

	// slow start increase
	tp->log_snd_cwnd(tp->snd_cwnd = std::min(cw + (u_int)std::floor(incr), static_cast<u_int>(TCP_MAXWIN << tp->snd_scale)));
}

void  L4_TCP::tcp_rto_timer_handler(tcpcb* tp)
{

}