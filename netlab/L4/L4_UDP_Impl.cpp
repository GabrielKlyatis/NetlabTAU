#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "L4_UDP_Impl.hpp"

/*******************************************************************************************************/
/*										 L4_UDP - IMPLEMENTATION									   */
/*******************************************************************************************************/

void L4_UDP_Impl::pr_input(const struct pr_input_args& args) {

	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);
	class inpcb_impl* inp(nullptr);
	const int& iphlen(args.iphlen);

	uint16_t udpiphdrlen(sizeof(udphdr) + sizeof(L3::iphdr));

	struct L4_UDP_Impl::udpiphdr* ui(reinterpret_cast<struct L4_UDP_Impl::udpiphdr*>(&m->data()[it - m->begin()]));

	// Strip options if needed.
	if (iphlen > sizeof(struct L3::iphdr))
		L3_impl::ip_stripoptions(m, it);

	if (m->end() - it < sizeof(struct udpiphdr)) {
		return drop(nullptr, 0);
	}

	int len(reinterpret_cast<struct L3::iphdr*>(ui)->ip_len);
	int ui_len(len - sizeof(struct L3::iphdr));

	ui->ui_next(0);
	ui->ui_prev(0);
	ui->ui_x1() = 0;
	ui->ui_len() = htons((uint16_t)ui_len);

	u_short checksum(ui->ui_sum());
	if (((ui->ui_sum() = 0) = checksum ^ inet.in_cksum(&m->data()[it - m->begin()], len)) != 0)
		return drop(nullptr, 0);

	inp = udp_last_inpcb;

	if ((inp->inp_lport() != ui->ui_dport() ||
		inp->inp_fport() != ui->ui_sport() ||
		inp->inp_faddr().s_addr != ui->ui_src().s_addr ||
		inp->inp_laddr().s_addr != ui->ui_dst().s_addr) &&
		(inp = udb.in_pcblookup(ui->ui_src(), ui->ui_sport(), ui->ui_dst(), ui->ui_dport(), inpcb::INPLOOKUP_WILDCARD))) {

		udp_last_inpcb = inp;
	}


	// Create UDP control block.
	L4_UDP::udpcb* up = L4_UDP::udpcb::intoudpcb(inp);

	// Create socket
	socket* so(dynamic_cast<socket*>(up->inp_socket));

	up = L4_UDP::udpcb::sotoudpcb(so);
	up->inp_laddr() = ui->ui_dst();

	long data_len = m->end() - it - sizeof(struct udpiphdr);

	// Copy data
	if (data_len > 0) {

		auto view = boost::make_iterator_range(it + sizeof(struct udpiphdr), m->end());
		so->so_rcv.sbappends(view);
		so->sorwakeup();
		return;
	}
}


int L4_UDP_Impl::udp_output(L4_UDP::udpcb& up) {

	socket* so = dynamic_cast<socket*>(up.udp_inpcb->inp_socket);

	long len(so->so_snd.size());

	uint16_t udpiphdrlen(sizeof(udphdr) + sizeof(L3::iphdr));

	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(udpiphdrlen + sizeof(struct L2::ether_header) + len));
	if (m == nullptr)
		return out(up, ENOBUFS);

	std::vector<byte>::iterator it(m->begin() + sizeof(struct L2::ether_header));

	// Copy data
	if (len > 0) {

		auto slot = boost::make_iterator_range(it + udpiphdrlen, it + udpiphdrlen + len);
		so->so_snd.sbfill(slot, true);

		struct L4_UDP_Impl::udpiphdr* ui = reinterpret_cast<struct L4_UDP_Impl::udpiphdr*>(&m->data()[it - m->begin()]);

		ui->ui_x1() = 0;
		ui->ui_pr() = IPPROTO_UDP;
		ui->ui_len() = htons((uint16_t)(len + sizeof(udphdr)));
		ui->ui_src() = so->so_pcb->inp_laddr();
		ui->ui_dst() = so->so_pcb->inp_faddr();
		ui->ui_sport() = so->so_pcb->inp_lport();
		ui->ui_dport() = so->so_pcb->inp_fport();
		ui->ui_ulen() = ui->ui_len();
		ui->ui_sum() = 0;
		ui->ui_sum() = inet.in_cksum(&m->data()[it - m->begin()], static_cast<int>(udpiphdrlen + len));

		reinterpret_cast<struct L3::iphdr*>(ui)->ip_len = static_cast<short>(udpiphdrlen + len);
		reinterpret_cast<struct L3::iphdr*>(ui)->ip_ttl = up.udp_inpcb->inp_ip.ip_ttl;	/* XXX */
		reinterpret_cast<struct L3::iphdr*>(ui)->ip_tos = up.udp_inpcb->inp_ip.ip_tos;	/* XXX */

		// Send encapsualted result with udp header to IP layer
		int error(
			inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*dynamic_cast<const struct pr_output_args*>(
				&L3_impl::ip_output_args(m, it, up.udp_inpcb->inp_options, &up.udp_inpcb->inp_route, so->so_options & SO_DONTROUTE, nullptr)
				)));
		if (error)
			return out(up, error);
	}

	return 0;
}

int L4_UDP_Impl::pr_output(const struct pr_output_args& args) {
	return udp_output(reinterpret_cast<const struct udp_output_args*>(&args)->up);
};