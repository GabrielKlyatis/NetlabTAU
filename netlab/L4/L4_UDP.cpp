#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "L4_UDP_Impl.hpp"

/*******************************************************************************************************/
/*										 L4_UDP - INTERFACE											   */
/*******************************************************************************************************/

L4_UDP::L4_UDP(class inet_os& inet) : protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP) { }


/************************************************************************/
/*                         udp_output_args                               */
/************************************************************************/

L4_UDP_Impl::udp_output_args::udp_output_args(L4_UDP::udpcb& up) : up(up) { }

/************************************************************************/
/*                         L4_UDP::udpcb                                */
/************************************************************************/

L4_UDP::udpcb::udpcb(inet_os& inet)
	: inpcb_impl(inet), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

L4_UDP::udpcb::udpcb(socket& so, inpcb_impl& head)
	: inpcb_impl(so, head), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

L4_UDP::udpcb::~udpcb() {

	if (this != dynamic_cast<class L4_UDP::udpcb*>(udp_inpcb))
		delete udp_inpcb;
}

/************************************************************************/
/*                         L4_UDP_Impl::udphdr                          */
/************************************************************************/

std::ostream& operator<<(std::ostream& out, const struct L4_UDP_Impl::udphdr& udp) {

	std::ios::fmtflags f(out.flags());
	out << "< UDP (" << "SourcePort = " << std::dec << ntohs(static_cast<uint16_t>(udp.uh_sport)) <<
		" , DestinationPort = " << std::dec << ntohs(static_cast<uint16_t>(udp.uh_dport)) <<
		" , HeaderLength = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(udp.uh_ulen) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(3) << std::hex << static_cast<uint16_t>(udp.uh_sum) <<
		" )";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                    L4_UDP_Impl::udpiphdr::ipovly                     */
/************************************************************************/

L4_UDP_Impl::udpiphdr::ipovly::ipovly()
	: ih_pr(0), ih_len(0), ih_src(struct in_addr()), ih_dst(struct in_addr()), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

L4_UDP_Impl::udpiphdr::ipovly::ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst)
	: ih_pr(ih_pr), ih_len(ih_len), ih_src(ih_src), ih_dst(ih_dst), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

std::ostream& operator<<(std::ostream& out, const struct L4_UDP_Impl::udpiphdr::ipovly& ip) {
	std::ios::fmtflags f(out.flags());
	out << "< Pseudo IP (" << static_cast<uint32_t>(sizeof(struct L4_UDP_Impl::udpiphdr::ipovly)) <<
		" bytes) :: Unsused = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_x1) <<
		" , Protocol = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_pr) <<
		" , Protocol Length = " << std::dec << htons(static_cast<uint16_t>(ip.ih_len)) <<
		" , SourceIP = " << inet_ntoa(ip.ih_src);
	out << " , DestinationIP = " << inet_ntoa(ip.ih_dst) <<
		" , >";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                         L4_UDP_Impl::udpiphdr                        */
/************************************************************************/

L4_UDP_Impl::udpiphdr::udpiphdr() : ui_i(ipovly()), ui_u(udphdr()) { }

std::ostream& operator<<(std::ostream& out, const struct L4_UDP_Impl::udpiphdr& ui)
{
	return out << ui.ui_i << ui.ui_u;
}

inline void L4_UDP_Impl::udpiphdr::insque(struct L4_UDP_Impl::udpiphdr& head)
{
	ui_next(head.ui_next());
	head.ui_next(this);
	ui_prev(&head);
	if (ui_next())
		ui_next()->ui_prev(this);
}

inline void L4_UDP_Impl::udpiphdr::remque()
{
	if (ui_next())
		ui_next()->ui_prev(ui_prev());
	if (ui_prev()) {
		ui_prev()->ui_next(ui_next());
		ui_prev(nullptr);
	}
}


/************************** UTILS *********************************/

uint16_t ones_complement_add(uint16_t a, uint16_t b) {
	uint32_t sum = a + b; // Use a larger type to capture potential carry
	// Handle end-around carry
	while (sum > 0xFFFF) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<uint16_t>(sum); // Convert back to 16 bits
}

/************************************************************************/
/*                         L4_UDP_Impl			                        */
/************************************************************************/

L4_UDP_Impl::L4_UDP_Impl(class inet_os& inet)
	: L4_UDP(inet), udb(inet), udp_last_inpcb(nullptr) {}

L4_UDP_Impl::~L4_UDP_Impl() {
	if (udp_last_inpcb)
		delete udp_last_inpcb;
}

void L4_UDP_Impl::pr_init() {

	udb.inp_next = udb.inp_prev = &udb;
	udp_last_inpcb = nullptr;
	udp_last_inpcb = dynamic_cast<class inpcb_impl*>(&udb);
}

int L4_UDP_Impl::pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
	struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) {

	class inpcb* inp(so->so_pcb);
	class L4_UDP::udpcb* up(nullptr);
	up = L4_UDP::udpcb::intoudpcb(inp);

	if (inp == nullptr && req != PRU_ATTACH)
		return (EINVAL);

	int error{ 0 };

	switch (req) {

	case PRU_ATTACH:
	{
		if (inp) {
			error = EISCONN;
			break;
		}
		if (error = udp_attach(*dynamic_cast<socket*>(so)))
			break;
		up = L4_UDP::udpcb::sotoudpcb(dynamic_cast<socket*>(so));
		break;
	}

	case PRU_DETACH:
	{
		break;
	}

	case PRU_BIND:
	{
		if (error = inp->in_pcbbind(reinterpret_cast<struct sockaddr_in*>(nam), nam_len))
			break;
		break;
	}

	case PRU_SEND:
	{
		if (inp->inp_lport() == 0)
			if (error = inp->in_pcbbind(nullptr, 0))
				break;

		if (error = inp->in_pcbconnect(reinterpret_cast<sockaddr_in*>(const_cast<struct sockaddr*>(nam)), nam_len))
			break;
		dynamic_cast<socket*>(so)->so_snd.sbappends(*m);
		error = udp_output(*up);
		break;
	}
	}
	return error;
}

int L4_UDP_Impl::udp_attach(socket& so)
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
	if ((dynamic_cast<socket*>(&so)->so_snd.capacity() == 0 || dynamic_cast<socket*>(&so)->so_rcv.capacity() == 0) && (error = dynamic_cast<socket*>(&so)->soreserve(10000, 10000)))
		return (error);

	/*
	 *	Allocate Internet PCB and UDP control block:
	 *	inpcb allocates an Internet PCB and here we allocate a UDP control block and links it to the PCB.
	 */


	class L4_UDP::udpcb* up(new L4_UDP::udpcb(so, udb));
	//up->seg_next = tp->seg_prev = reinterpret_cast<struct L4_UDP::tcpiphdr*>(up);
	if (up->udp_inpcb == nullptr)
		up->udp_inpcb = dynamic_cast<class inpcb_impl*>(up);

	up->udp_inpcb->inp_ip.ip_ttl = L3_impl::IPDEFTTL;
	up->udp_inpcb->inp_ppcb = dynamic_cast<class inpcb_impl*>(up);

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
	if (up == nullptr) {
		const int nofd(so.so_state & socket::SS_NOFDREF);	/* XXX */
		so.so_state &= ~socket::SS_NOFDREF;	/* don't free the socket yet */
		so.so_state |= nofd;
		return (ENOBUFS);
	}
	return (0);
}