#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "L4_UDP_Impl.hpp"

L4_UDP::L4_UDP(class inet_os& inet) : protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP) { }


/************************************************************************/
/*                         udp_output_args                               */
/************************************************************************/

L4_UDP_Impl::udp_output_args::udp_output_args(L4_UDP::udpcb &up) : up(up){ }

/************************************************************************/
/*                         L4_UDP::udpcb                                */
/************************************************************************/

L4_UDP::udpcb::udpcb(inet_os& inet)
	: inpcb_impl(inet), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

L4_UDP::udpcb::udpcb(socket& so, inpcb_impl& head)
	: inpcb_impl(so, head), udp_ip_template(nullptr), udp_inpcb(dynamic_cast<inpcb_impl*>(this)),
	log(udpcb_logger()) { }

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

L4_UDP_Impl::udpiphdr::udpiphdr(const in_addr& ip_src_addr, const in_addr& ip_dst_addr, const u_char& protocol, const short& udp_length) 
	: ip_src_addr(ip_src_addr), ip_dst_addr(ip_dst_addr), protocol(protocol), udp_length(udp_length) { } 

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

uint16_t L4_UDP_Impl::calculate_checksum(udpiphdr& udp_pseudo_header, std::shared_ptr<std::vector<byte>>& m) {

	uint16_t checksum = 0;
	uint8_t* byte_ptr = reinterpret_cast<uint8_t*>(&udp_pseudo_header);
	uint16_t udp_pseudo_header_length = sizeof(udp_pseudo_header);

	for (size_t i = 0; i < udp_pseudo_header_length; i += 2) {

		uint16_t word = 0;
		word = (byte_ptr[i] << 8) + byte_ptr[i + 1];

		checksum = ones_complement_add(checksum, word);
	}

	byte_ptr = reinterpret_cast<uint8_t*>(&(*(m->begin() + sizeof(L2::ether_header) + sizeof(L3::iphdr))));

	auto udp_length_in_host = ntohs(udp_pseudo_header.udp_length);

	for (size_t i = 0; i < udp_length_in_host; i += 2) {

		uint16_t word = 0;
		if ((udp_length_in_host % 2) != 0) {
			word = (byte_ptr[i] << 8);
		}
		else {
			word = (byte_ptr[i] << 8) + byte_ptr[i + 1];
		}
		checksum = ones_complement_add(checksum, word);
	}

	return ~checksum;
}


/************************************************************************/
/*                         L4_UDP_Impl			                        */
/************************************************************************/

L4_UDP_Impl::L4_UDP_Impl(class inet_os &inet)
	: L4_UDP(inet), ucb(inet), udp_last_inpcb(nullptr) {}

L4_UDP_Impl::~L4_UDP_Impl() {
	if (udp_last_inpcb)
		delete udp_last_inpcb;
}

void L4_UDP_Impl::pr_init() {
	ucb.inp_next = ucb.inp_prev = &ucb;
	udp_last_inpcb = nullptr;
	udp_last_inpcb = dynamic_cast<class inpcb_impl*>(&ucb);
}


void L4_UDP_Impl::pr_input(const struct pr_input_args& args) {
	
	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);
	const int& iphlen(args.iphlen);
	const int& udphlen(sizeof(udphdr));
	
	// Strip options if needed.
	if (iphlen > sizeof(struct L3::iphdr))
		L3_impl::ip_stripoptions(m, it);

	if (m->end() - it < (iphlen + sizeof(udphdr))) { // why??
		return drop(nullptr, 0);
	}

	// Get IP header from buffer
	struct L3::iphdr* ip_header = reinterpret_cast<struct L3::iphdr*>(&(*it));

	// Get UDP header from buffer
	struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(&(*(it+iphlen)));

	// Calculate UDP pseudo header and checksum 
	struct udpiphdr udp_pseudo_header(ip_header->ip_src, ip_header->ip_dst, IPPROTO_UDP, udp_header->uh_ulen);

	int len(sizeof(struct L3::iphdr) + ip_header->ip_len);
	
	uint16_t udp_checksum = calculate_checksum(udp_pseudo_header, m);

	if (udp_checksum != 0) {
		return drop(nullptr, 0); // TODO
	}

	class inpcb_impl* inp(nullptr);
	
	inp = udp_last_inpcb;

	if ((inp->inp_lport() != udp_header->uh_dport ||
		inp->inp_fport() != udp_header->uh_sport ||
		inp->inp_faddr().s_addr != ip_header->ip_src.s_addr ||
		inp->inp_laddr().s_addr != ip_header->ip_dst.s_addr) &&
		(inp = ucb.in_pcblookup(ip_header->ip_src, udp_header->uh_sport, ip_header->ip_dst, udp_header->uh_dport, inpcb::INPLOOKUP_WILDCARD))) {

		udp_last_inpcb = inp;
	}


	// Create UDP control block.
	L4_UDP::udpcb* up = L4_UDP::udpcb::intoudpcb(inp);

	// Create socket
	socket* so(dynamic_cast<socket*>(up->inp_socket));

	up = L4_UDP::udpcb::sotoudpcb(so);
	up->inp_laddr() = ip_header->ip_dst;

	long data_len = m->end() - it - udphlen - iphlen;

	// Copy data
	if (data_len > 0) {

		so->so_rcv.sbappend(it + udphlen + iphlen, it + udphlen + iphlen + data_len);
		so->sorwakeup();
		return;
	}
}


int L4_UDP_Impl::udp_output(L4_UDP::udpcb& up) {

	socket *so = dynamic_cast<socket *>(up.udp_inpcb->inp_socket);

	long len(so->so_snd.size());

	uint16_t hdrlen(sizeof(udphdr) + sizeof(L3::iphdr));

	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(hdrlen + sizeof(struct L2::ether_header) + len));
	if (m == nullptr)
		return out(up, ENOBUFS);

	std::vector<byte>::iterator it(m->begin() + sizeof(struct L2::ether_header) + sizeof(L3::iphdr));

	if (len > 0) {

		// Copy data
		std::copy(so->so_snd.begin(), so->so_snd.begin() + len, it + sizeof(udphdr));

		// Create udp header
		struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(&(*it));

		// Update header
		udp_header->uh_dport = so->so_pcb->inp_fport();
		udp_header->uh_sport = so->so_pcb->inp_lport();
		udp_header->uh_ulen = htons((uint16_t)(len + sizeof(udphdr)));

		// Create atrophied IP header with only src and dst IP addresses

		struct L3::iphdr* ip_header = reinterpret_cast<struct L3::iphdr*> (&(*(it - sizeof(L3::iphdr))));

		ip_header->ip_src = so->so_pcb->inp_laddr();
		ip_header->ip_dst = so->so_pcb->inp_faddr();
		ip_header->ip_len = len + hdrlen;
		ip_header->ip_ttl = 99;
		ip_header->ip_p = IPPROTO_UDP;

		// Calculate UDP pseudo header and checksum 

		struct udpiphdr udp_pseudo_header(ip_header->ip_src, ip_header->ip_dst, IPPROTO_UDP, udp_header->uh_ulen);
		udp_header->uh_sum = htons(calculate_checksum(udp_pseudo_header, m));

		// Send encapsualted result with udp header to IP layer

		int error(
			inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*dynamic_cast<const struct pr_output_args*>(
				&L3_impl::ip_output_args(m, it - sizeof(L3::iphdr), up.udp_inpcb->inp_options, &up.udp_inpcb->inp_route, so->so_options & SO_DONTROUTE, nullptr)
				)));
		if (error)
			return out(up, error);

	}
	return 0;
}

int L4_UDP_Impl::pr_output(const struct pr_output_args& args) { 
	return udp_output(reinterpret_cast<const struct udp_output_args*>(&args)->up);
};

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
			dynamic_cast<socket*>(so)->so_snd.sbappend(m->begin(), m->end());
			error = udp_output(*up);
			break;
		}
	}
	return error;
}

void L4_UDP_Impl::drop(class inpcb_impl* inp, const int dropsocket) {

	/*
	* Drop space held by incoming segment and return.
	*
	* destroy temporarily created socket
	*/
	if (dropsocket && inp)
		(void)dynamic_cast<socket*>(inp->inp_socket)->soabort();
	return;
}

int L4_UDP_Impl::out(L4_UDP::udpcb& up, int error)
{
	return (error);
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

	
	class L4_UDP::udpcb* up(new L4_UDP::udpcb(so, ucb));
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