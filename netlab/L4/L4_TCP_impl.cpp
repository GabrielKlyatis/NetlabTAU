#include "L4_TCP_impl.h"

/***************************************************************************************/
/*							L4_TCP_impl - Student Implementation					   */
/***************************************************************************************/

/*
	Constructor - IMPLEMENTED FOR YOU
		* inet - The inet.
*/
L4_TCP_impl::L4_TCP_impl(class inet_os& inet) : L4_TCP(inet) { }

/*
	Destructor - IMPLEMENTED FOR YOU
	Deletes the tcp_saveti, and the tcp_last_inpcb if space has been allocated for them.
*/
L4_TCP_impl::~L4_TCP_impl()
{
	if (tcp_saveti)
		delete tcp_saveti;
	if (tcp_last_inpcb)
		delete tcp_last_inpcb;
}

// // Wrapper for tcp_output.
int L4_TCP_impl::pr_output(const struct pr_output_args& args)
{
	return tcp_output(reinterpret_cast<const struct tcp_output_args*>(&args)->tp);
}

/*
	tcp_output Function - The actual function, with the desired arguments. This function handles the transmission of TCP segments.

		It constructs TCP headers, segments data to fit the Maximum Segment Size (MSS), applies flow control (using cwnd and rwnd),
		and manages retransmissions for reliability. It computes checksums, attaches options (like SACK or timestamps),
		updates sequence numbers, and passes packets to the IP layer for transmission.
		The function ensures compliance with TCP's flow control, congestion control,
		and retransmission mechanisms to maintain reliable data delivery.

		* tp - The TCP control block of this connection.
*/
int L4_TCP_impl::tcp_output(class tcpcb& tp)
{
	/*
	*	Is an ACK expected from the other end?
	*	idle is true if the maximum sequence number sent (snd_max) equals the oldest
	*	unacknowledged sequence number (snd_una), that is, if an ACK is not expected from
	*	the other end.
	*
	* Determine length of data that should be transmitted,
	* and flags that will be used.
	* If there is some data or critical controls (SYN, RST)
	* to send, then transmit; otherwise, investigate further.
	*/
	bool idle(tp.snd_max == tp.snd_una);
	if (idle && tp.t_idle >= tp.t_rxtcur)

		/*
		 *	Go back to slow start:
		 *	If an ACK is not expected from the other end and a segment has not been received
		 *	from the other end in one RTO, the congestion window is set to one segment
		 *	t_maxseg bytes). This forces slow start to occur for this connection the next time a
		 *	segment is sent. When a significant pause occurs in the data transmission ("significant"
		 *	being more than the RTf), the network conditions can change from what was previously
		 *	measured on the connection. Net/3 assumes the worst and returns to slow start.
		 *
		* We have been idle for "a while" and no acks are
		* expected to clock out any data we send --
		* slow start to get ack "clock" running again.
		*/
		tp.log_snd_cwnd(tp.snd_cwnd = tp.t_maxseg);

	/*
	*	Send more than one segment:
	*	When send is jumped to, a single segment is sent by calling ip_output. But if
	*	tcp_output determines that more than one segment can be sent, sendalot is set to 1,
	*	and the function tries to send another segment. Therefore, one call to tcp_output can
	*	result in multiple segments being sent.
	*/
	return again(tp, idle, *dynamic_cast<socket*>(tp.t_inpcb->inp_socket));
}

/*
	pr_input function - This function handles the reception of TCP segments.
	It validates the TCP header, checks the checksum, and handles demultiplexing to the appropriate connection based on the
	socket and port numbers. It manages sequence numbers, acknowledges received data, and processes TCP options like SACK or
	timestamps. Depending on the state of the connection (e.g., SYN_RECEIVED, ESTABLISHED), it updates the Transmission Control Block (TCB),
	handles retransmissions, and passes received data to the application layer.

		* args - The arguments to the protocol, which include:
				- m - The std::shared_ptr<std::vector<byte>> to process.
				- it - The iterator, as the current offset in the vector.
				- iphlen - The IP header length.
*/
void L4_TCP_impl::pr_input(const struct pr_input_args& args)
{
	std::shared_ptr<std::vector<byte>>& m(args.m);
	std::vector<byte>::iterator& it(args.it);
	const int& iphlen(args.iphlen);

	/*
	 *	Get IP and TCP headers In first mbuf
	 *	The argument iphlen is the length of the IP header, including possible IP options.
	 *	If the length is greater than 20 bytes, options are present, and ip_stripoptions discards
	 *	the options. TCP ignores all IP options other than a source route, which is saved
	 *	specially by IP (Section 9.6) and fetched later by TCP in Figure 28.7. If the number of
	 *	bytes in the first mbuf in the chain is less than the size of the combined IP /TCP header
	 *	(40 bytes), m_pullup moves the first 40 bytes into the first mbuf.
	 *
	* Get IP and TCP header together in first mbuf.
	* Note: IP leaves IP header in first mbuf.
	*/
	struct tcpiphdr* ti(reinterpret_cast<struct tcpiphdr*>(&m->data()[it - m->begin()]));

	if (iphlen > sizeof(struct L3::iphdr))
		L3_impl::ip_stripoptions(m, it);

	if (m->end() - it < sizeof(struct tcpiphdr))
		return drop(nullptr, 0);

	/*
	 *	Verify TCP checksum
	 *	tlen is the TCP length, the number of bytes following the IP header. Recall that IP
	 *	has already subtracted the IP header length from ip_len. The variable len is then set
	 *	to the length of the IP datagram, the number of bytes to be checksummed, including the
	 *	pseudo-header. The fields in the pseudo-header are set, as required for the checksum
	 *	calculation, as shown in Figure 23.19.
	 *
	* Checksum extended TCP header and data.
	*/
	int tlen(reinterpret_cast<struct L3::iphdr*>(ti)->ip_len),
		len(sizeof(struct L3::iphdr) + tlen);

	ti->ti_next(0);
	ti->ti_prev(0);
	ti->ti_x1() = 0;
	ti->ti_len() = htons(static_cast<u_short>(tlen));

	u_short checksum(ti->ti_sum());
	if (((ti->ti_sum() = 0) = checksum ^ inet.in_cksum(&m->data()[it - m->begin()], len)) != 0)
		return drop(nullptr, 0);

	/*
	 *	Verify TCP offset field
	 *	The TCP offset field, ti_off, is the number of 32-bit words in the TCP header,
	 *	including any TCP options. It is multiplied by 4 (to become the byte offset of the first
	 *	data byte in the TCP segment) and checked for sanity. It must be greater than or equal
	 *	to the size of the standard TCP header (20) and less than or equal to the TCP length.
	 *
	* Check that TCP offset makes sense,
	* pull out TCP options and adjust length.		XXX
	*/
	int off(ti->ti_off() << 2);
	if (off < sizeof(struct tcphdr) || off > tlen)
		return drop(nullptr, 0);

	/*
	 *	The byte offset of the first data byte is subtracted from the TCP length, leaving tlen
	 *	with the number of bytes of data in the segment (possibly 0). This value is stored back
	 *	into the TCP header, in the variable ti_len, and will be used throughout the function.
	 */
	ti->ti_len() = (tlen -= off);

	/*
	*	Get headers plus option Into first mbuf
	*	If the byte offset of the first data byte is greater than 20, TCP options are present.
	*/
	u_char* optp(nullptr);
	int optlen,
		ts_present(0);
	u_long ts_val,
		ts_ecr;

	if (off > sizeof(struct tcphdr)) {

		/*
		*	Process timestamp option quickly:
		*	optlen is the number of bytes of options, and optp is a pointer to the first option
		*	byte.
		*/
		optlen = off - sizeof(struct tcphdr);
		optp = &m->data()[it - m->begin() + sizeof(struct tcpiphdr)];

		/*
		 *	If the following three conditions are all true, only the timestamp option is present
		 *	and it is in the desired format
		 *		1.	(a) The TCP option length equals 12 (TCPOLEN_TSTAMP_APPA), or
		 *			(b) the TCP Option length is greater than 12 and optp[12] equals the end-0f-option byte.
		 *		2.	The first 4 bytes of options equals Ox0101080a (TCPOPT_TSTAMP_HDR)
		 *		3.	The SYN flag is not set (i.e., this segment is for an established connection, hence
		 *			if a timestamp option is present, we know both sides have agreed to use the
		 *			option).
		 *
		* Do quick retrieval of timestamp options ("options
		* prediction?").  If timestamp is the only option and it's
		* formatted as recommended in RFC 1323 appendix A, we
		* quickly get the values now and not bother calling
		* tcp_dooptions(), etc.
		*/
		if ((optlen == TCPOLEN_TSTAMP_APPA ||
			(optlen > TCPOLEN_TSTAMP_APPA &&
				optp[TCPOLEN_TSTAMP_APPA] == TCPOPT_EOL)) &&
			*reinterpret_cast<u_long*>(optp) == htonl(TCPOPT_TSTAMP_HDR) &&
			(ti->ti_flags() & tcphdr::TH_SYN) == 0)
		{

			/*
			 *	If all three conditions are true, ts_present is set to 1;
			 *	the two timestamp values are fetched and stored in ts_ val and ts_ecr;
			 *	and optp is set to null, since all the options have been parsed.
			 *	The benefit in recognizing the timestamp option this way is to avoid
			 *	calling the general option processing function tcp_dooptions later in the code. The
			 *	general option processing function is OK for the other options that appear only with the
			 *	SYN segment that creates a connection (the MSS and window scale options), but when
			 *	the timestamp option is being used, it will appear with almost every segment on an
			 *	established connection, so the faster it can be recognized, the better.
			 */
			ts_present = 1;
			ts_val = ntohl(*reinterpret_cast<u_long*>(&optp[4]));
			ts_ecr = ntohl(*reinterpret_cast<u_long*>(&optp[8]));
			optp = nullptr;	/* we've parsed the options */
		}
	}

	int tiflags(ti->ti_flags());

	/*
	 *	Save Input flags and convert fields to host byte order:
	 *	The received flags (SYN, FIN, etc.) are saved in the local variable ti_flags, since
	 *	they are referenced throughout the code. Two 16-bit values and the two 32-bit values in
	 *	the TCP header are converted from network byte order to host byte order. The two
	 *	16-bit port numbers are left in network byte order, since the port numbers in the Internet
	 *	PCB are in that order.
	 *
	* Convert TCP protocol specific fields to host format.
	*/
	ti->ti_seq() = ntohl(ti->ti_seq());
	ti->ti_ack() = ntohl(ti->ti_ack());
	ti->ti_win() = ntohs(ti->ti_win());
	ti->ti_urp() = ntohs(ti->ti_urp());

	//#define NETLAB_L4_TCP_DEBUG
#ifdef NETLAB_L4_TCP_DEBUG
	print(ti->ti_t, htons(checksum));
#endif

	/*
	 *	Locate Internet PCB:
	 *	TCP maintains a one-behind cache (tcp_last_inpcb) containing the address of
	 *	the PCB for the last received TCP segment. This is the same technique used by UDP.
	 *	The comparison of the four elements in the socket pair is in the same order as done by
	 *	udp_input. If the cache entry does not match, in_pcblookup is called, and the cache
	 *	is set to the new PCB entry.
	 *	TCP does not have the same problem that we encountered with UDP: wildcard
	 *	entries in the cache causing a high miss rate. The only time a TCP socket has a wildcard
	 *	entry is for a server listening for connection requests. Once a connection is made, all
	 *	four entries in the socket pair contain nonwildcard values. In Figure 24.5 we see a cache
	 *	hit rate of almost 80°/o.
	* Locate pcb for segment.
	*/
	int dropsocket(0),
		iss(0);
	class inpcb_impl* inp(nullptr);

findpcb:
	inp = tcp_last_inpcb;
	if ((inp->inp_lport() != ti->ti_dport() ||
		inp->inp_fport() != ti->ti_sport() ||
		inp->inp_faddr().s_addr != ti->ti_src().s_addr ||
		inp->inp_laddr().s_addr != ti->ti_dst().s_addr) &&
		(inp = tcb.in_pcblookup(ti->ti_src(), ti->ti_sport(), ti->ti_dst(), ti->ti_dport(), inpcb::INPLOOKUP_WILDCARD)))
		tcp_last_inpcb = inp;

	/*
	 *	Drop segment and generate RST:
	 *	If the PCB was not found, the input segment is dropped and an RST is sent as a
	 *	reply. This is how TCP handles SYNs that arrive for a server that doesn't exist, for
	 *	example. Recall that UDP sends an ICMP port unreachable in this case.
	 *
	* If the state is CLOSED (i.e., TCB does not exist) then
	* all data in the incoming segment is discarded.
	* If the TCB exists but is in CLOSED state, it is embryonic,
	* but should either do a listen or a connect soon.
	*/
	if (inp == nullptr)
		return dropwithreset(nullptr, dropsocket, tiflags, m, it, ti);

	/*
	 *	If the PCB exists but a corresponding TCP control block does not exist, the socket is
	 *	probably being closed (tcp_close releases the TCP control block first, and then
	 *	releases the PCB), so the input segment is dropped and an RST is sent as a reply.
	 */
	class tcpcb* tp = tcpcb::intotcpcb(inp);
	if (tp == nullptr)
		return dropwithreset(inp, dropsocket, tiflags, m, it, ti);

	/*
	 *	Silently drop segment:
	 *	If the TCP control block exists, but the connection state is CLOSED, the socket has
	 *	been created and a local address and local port may have been assigned, but neither
	 *	connect nor listen has been called. The segment is dropped but nothing is sent as a
	 *	reply. This scenario can happen if a client catches a sender between the server's call to
	 *	bind and listen. By silently dropping the segment and not replying with an RST, the
	 *	client's connection request should time out, causing the client to retransmit the SYN.
	 */
	if (tp->t_state == tcpcb::TCPS_CLOSED)
		return drop(tp, dropsocket);

	/*
	 *	Unscale advertised window into a 32-bit value:
	 *	If window scaling is to take place for this connection, both ends must specify their
	 *	send scale factor using the window scale option when the connection is established. If
	 *	the segment contains a SYN, the window scale factor has not been established yet, so
	 *	tiwin is copied from the value in the TCP header. Otherwise the 16-bit value in the
	 *	header is left shifted by the send scale factor into a 32-bit value.
	 */
	u_long tiwin(ti->ti_win());
	if ((tiflags & tcphdr::TH_SYN) == 0)
		tiwin <<= tp->snd_scale;

	socket* so(dynamic_cast<socket*>(tp->inp_socket));
	if (so && so->so_options & (SO_DEBUG | SO_ACCEPTCONN)) {

		/*
		 *	Save connection state and IP/TCP headers If socket debug option enabled:
		 *	If the SO_DEBUG socket option is enabled the current connection state is saved
		 *	(ostate) as well as the IP and TCP headers (tcp_saveti). These become arguments
		 *	to tcp_trace when it is called at the end of the function (Figure 29.26).
		 */
		if (so->so_options & SO_DEBUG)
			tcp_saveti = ti;

		/*
		 *	Create new socket If segment arrives for listening socket:
		 *	When a segment arrives for a listening socket (SO_ACCEPTCONN is enabled by
		 *	listen), a new socket is created by sonewconn.
		 *	This issues the protocol's PRU_ATTACH request (Figure 30.2), which allocates an
		 *	Internet PCB and a TCP control block.
		 *	But more processing is needed before TCP commits to accept the connection
		 *	request (such as the fundamental question of whether the segment contains a SYN or
		 *	not), so the flag dropsocket is set, to cause the code at the labels drop and
		 *	dropwithreset to discard the new socket if an error is encountered. If the received
		 *	segment is OK, dropsocket is set back to 0 in Figure 28.17.
		 */
		if (so->so_options & SO_ACCEPTCONN) {
			if ((tiflags & (tcphdr::TH_RST | tcphdr::TH_ACK | tcphdr::TH_SYN)) != tcphdr::TH_SYN)

				/*
				* Note: dropwithreset makes sure we don't
				* send a reset in response to a RST.
				*/
				if (tiflags & tcphdr::TH_ACK)
					return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
				else
					return drop(tp, dropsocket);
			else if ((so = so->sonewconn(*so, 0)) == nullptr)
				return drop(tp, dropsocket);

			/*
			* This is ugly, but ....
			*
			* Mark socket as temporary until we're
			* committed to keeping it. The code at
			* "drop" and "dropwithreset" check the
			* flag dropsocket to see if the temporary
			* socket created here should be discarded.
			* We mark the socket as discardable until
			* we're committed to it below in TCPS_LISTEN.
			*/
			dropsocket++;

			/*
			 *	inp and tp point to the new socket that has been created. The local address and
			 *	local port are copied from the destination address and destination port of the IP and
			 *	TCP headers. If the input datagram contained a source route, it was saved by
			 *	save_rte. TCP calls ip_srcroute to fetch that source route, saving a pointer to the
			 *	mbuf containing the source route option in inp_options. This option is passed to
			 *	ip_output by tcp_output, and the reverse route is used for datagrams sent on this
			 *	connection.
			 */
			tp = tcpcb::sototcpcb(so);
			tp->inp_laddr() = ti->ti_dst();
			tp->inp_lport() = ti->ti_dport();

			/*
			 *	The state of the new socket is set to LISTEN. If the received segment contains a
			 *	SYN, the code in Figure 28.16 completes the connection request.
			 */
			tp->t_state = tcpcb::TCPS_LISTEN;

			/*
			 *	Compute window scale factor:
			 *	The window scale factor that will be requested is calculated from the size of the
			 *	receive buffer. 65535 (TCP_MAXWIN) is left shifted until the result exceeds the size of the
			 *	receive buffer, or until the maximum window scale factor is encountered (14, TCP MAX_WINSHIFT).
			 *	Notice that the requested window scale factor is chosen based on the size of the listening
			 *	socket's receive buffer. This means the process must set the SO_RCVBUF socket option before
			 *	listening for incoming connection requests or it inherits the default value in tcp_recvspace.
			 */
			while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
				static_cast<u_long>(TCP_MAXWIN) << tp->request_r_scale < so->so_rcv.capacity())
				tp->request_r_scale++;
		}
	}

	/*
	 *	Reset t_idle time and keepalive timer:
	 *	t_idle is set to 0 since a segment has been received on the connection.
	 *	The keepalive timer is also reset to 2 hours.
	* Segment received on connection.
	* Reset idle time and keep-alive timer.
	*/
	tp->t_idle = 0;
	tp->t_timer[TCPT_KEEP] = tcp_keepidle;

	/*
	 *	Process options if not in LISTEN state, else do it below (after getting remote address):
	 *	If options are present in the TCP header, and if the connection state is not LISTEN,
	 *	tcp_dooptions processes the options. Recall that if only a timestamp option appears
	 *	for an established connection, and that option is in the format recommended by Appendix
	 *	A of RFC 1323, it was already processed in Figure 28.4 and optp was set to a null
	 *	pointer. If the socket is in the LISTEN state, tcp_dooptions is called in Figure 28.17
	 *	after the peer's address has been recorded in the PCB, because processing the MSS
	 *	option requires knowledge of the route that will be used to this peer.
	 */
	if (optp && tp->t_state != tcpcb::TCPS_LISTEN)
		tcp_dooptions(*tp, optp, optlen, *ti, ts_present, ts_val, ts_ecr);

	/*
	 * Header prediction: check for the two common cases
	 * of a uni-directional data xfer. If the packet has
	 * no control flags, is in-sequence, the window didn't
	 * change and we're not retransmitting, it's a
	 * candidate. If the length is zero and the ack moved
	 * forward, we're the sender side of the xfer. Just
	 * free the data acked & wake any higher level process
	 * that was blocked waiting for space. If the length
	 * is non-zero and the ack didn't move, we're the
	 * receiver side. If we're getting packets in-order
	 * (the reassembly queue is empty), add the data to
	 * the socket buffer and note that we need a delayed ack.
	 *
	 *	Check If segment is the next expected:
	 *	The following six conditions must all be true for the segment to be the next expected
	 *	data segment or the next expected ACK:
	 *		1.	The connection state must be ESTABLISHED.
	 *		2.	The following four control flags must not be on: SYN, FIN, RST, or URG.
	 *			The	ACK flag must be on.
	 *			In other words, of the six TCP control flags, the ACK flag must be set,
	 *			the four just listed must be cleared, and it doesn't matter whether PSH
	 *			is set or cleared. (Normally in the ESTABLISHED state the ACK flag is
	 *			always on unless the RST flag is on.)
	 *		3.	If the segment contains a timestamp option, the timestamp value from the other
	 *			end (ts_val) must be greater than or equal to the previous timestamp received
	 *			for this connection (ts_recent). This is basically the PAWS test, which we
	 *			describe in detail in Section 28.7. If ts_val is less than ts_recent, this segment
	 *			is out of order because it was sent before the most previous segment
	 *			received on this connection. Since the other end always sends its timestamp
	 *			clock (the global variable tcp_now in Net/3) as its timestamp value, the
	 *			received timestamps of in-order segments always form a monotonic increasing
	 *			sequence.
	 *			The timestamp need not increase with every in-order segment. Indeed, on a
	 *			Net/3 system that increments the timestamp clock (tcp_now) every 500 ms,
	 *			multiple segments are often sent on a connection before that clock is incremented.
	 *			Think of the timestamp and sequence number as forming a 64-bit
	 *			value, with the sequence number in the low-order 32 bits and the timestamp in
	 *			the high-order 32 bits. This 64-bit value always increases by at least 1 for every
	 *			in-order segment (taking into account the modulo arithmetic).
	 *		4.	The starting sequence number of the segment (ti_seq) must equal the next
	 *			expected receive sequence number (rcv_nxt ). If this test is false, then the
	 *			received segment is either a retransmission or a segment beyond the one
	 *			expected.
	 *		5.	The window advertised by the segment (tiwin) must be nonzero, and must
	 *			equal the current send window (snd_wnd). This means the window has not changed.
	 *		6.	The next sequence number to send (snd_nxt) must equal the highest sequence
	 *			number sent (snd_max). This means the last segment sent by TCP was not a retransmission.
	*/
	if (tp->t_state == tcpcb::TCPS_ESTABLISHED &&
		(tiflags & (tcphdr::TH_SYN | tcphdr::TH_FIN | tcphdr::TH_RST | tcphdr::TH_URG | tcphdr::TH_ACK)) == tcphdr::TH_ACK &&
		(!ts_present || TSTMP_GEQ(ts_val, tp->ts_recent)) &&
		ti->ti_seq() == tp->rcv_nxt &&
		tiwin && tiwin == tp->snd_wnd &&
		tp->snd_nxt == tp->snd_max)
	{
		/*
		 *	Update ts_recent from received timestamp:
		 *	If a timestamp option is present and if its value passes the test described with Figure
		 *	26.18, the received timestamp (ts_val) is saved in ts_recent. Also, the current
		 *	time (tcp_now) is recorded in ts_recent_age.
		 *	Recall our discussion with Figure 26.18 on how this test for a valid timestamp is flawed, and
		 *	the correct test presented in Figure 26.20. In this header prediction code the TSTMP_GEQ test in
		 *	Figure 26.20 is redundant, since it was already done as step 3 of the if test at the beginning of
		 *	Figure 28.11.
		 *
		* If last ACK falls within this segment's sequence numbers,
		*  record the timestamp.
		*/
		if (ts_present && tcpcb::SEQ_LEQ(ti->ti_seq(), tp->last_ack_sent) &&
			tcpcb::SEQ_LT(tp->last_ack_sent, ti->ti_seq() + ti->ti_len()))
		{
			tp->ts_recent_age = tcp_now;
			tp->ts_recent = ts_val;
		}

		/*
		*	Test for pure ACK:
		*	If the following four conditions are all true, this segment is a pure ACK.
		*		1.	The segment contains no data (ti_len is 0).
		*		2.	The acknowledgment field in the segment (ti_ack) is greater than the largest
		*			unacknowledged sequence number (snd_una). Since this test is "greater than"
		*			and not "greater than or equal to," it is true only if some positive amount of
		*			data is acknowledged by the ACK.
		*		3.	The acknowledgment field in the segment (ti_ack) is less than or equal to the
		*			maximum sequence number sent (snd_max).
		*		4.	The congestion window (snd_cwnd) is greater than or equal to the current send
		*			window (snd_wnd). This test is true only if the window is fully open, that is,
		*			the connection is not in the middle of slow start or congestion avoidance.
		*/
		if ((ti->ti_len() == 0) &&
			(tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_una) &&
				tcpcb::SEQ_LEQ(ti->ti_ack(), tp->snd_max) &&
				tp->snd_cwnd >= tp->snd_wnd))
		{
			/*	This is a pure ack for outstanding data.
			*
			*	Update RTT estimators:
			*	If the segment contains a timestamp option, or if a segment was being timed and
			*	the acknowledgment field is greater than the starting sequence number being timed,
			*	tcp_xmi t_timer updates the RTT estimators.
			*/
			if (ts_present)
				tp->tcp_xmit_timer(static_cast<short>(tcp_now - ts_ecr + 1));
			else if (tp->t_rtt && tcpcb::SEQ_GT(ti->ti_ack(), tp->t_rtseq))
				tp->tcp_xmit_timer(tp->t_rtt);

			/*
			*	Delete acknowledged bytes from send buffer:
			*	acked is the number of bytes acknowledged by the segment. sbdrop deletes those
			*	bytes from the send buffer. The largest unacknowledged sequence number (snd_una)
			*	is set to the acknowledgment field and the received mbuf chain is released. (Since the
			*	length is 0, there should be just a single mbuf containing the headers.)
			*/
			so->so_snd.sbdrops(ti->ti_ack() - tp->snd_una);
			tp->snd_una = ti->ti_ack();

			/*
			*	Stop retransmit timer:
			*	If the received segment acknowledges all outstanding data (snd_una equals
			*	snd_max), the retransmission timer is turned off. Otherwise, if the persist timer is off,
			*	the retransmit timer is restarted using t_rxtcur as the timeout.
			*	Recall that when tcp_output sends a segment, it sets the retransmit timer only if
			*	the timer is not currently enabled. If two segments arc sent one right after the other, the
			*	timer is set when the first is sent, but not touched when the second is sent. But if an
			*	ACK is received only for the first segment, the retransmit timer must be restarted, in
			*	case the second was lost.
			*
			* If all outstanding data are acked, stop
			* retransmit timer, otherwise restart timer
			* using current (possibly backed-off) value.
			* If process is waiting for space,
			* wakeup/selwakeup/signal.  If data
			* are ready to send, let tcp_output
			* decide between more output or persist.
			*/
			if (tp->snd_una == tp->snd_max)
				tp->t_timer[TCPT_REXMT] = 0;
			else if (tp->t_timer[TCPT_PERSIST] == 0)
				tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

			/*
			*	Awaken waiting processes:
			*	If a process must be awakened when the send buffer is modified, sowwakeup is
			*	called. From Figure 16.5, SB_NOTIFY is true if a process is waiting for space in the buffer,
			*	if a process is selecting on the buffer, or if a process wants the SIGIO signal for
			*	this socket.
			*/
			if (so->so_snd.sb_flags & netlab::L5_socket::sockbuf::SB_NOTIFY)
				so->sowwakeup();

			/*
			*	Generate more output:
			*	If there is data in the send buffer, tcp_output is called because the sender's window
			*	has moved to the right. snd_una was just incremented and snd_wnd did not
			*	change, so in Figure 24.17 the entire window has shifted to the right.
			*/
			if (so->so_snd.size())
				(void)tcp_output(*tp);

			return;
		}

		/*
		 *	The next part of header prediction is the receiver processing when the segment is the next in-sequence data segment.
		 *
		 *	Test for next In-sequence data segment:
		 *	If the following four conditions are all true, this segment is the next expected data
		 *	segment for the connection, and there is room in the socket buffer for the data:
		 *		1.	The amount of data in the segment (ti_len) is greater than 0. This is the else
		 *			portion of the if at the beginning of Figure 28.12.
		 *		2.	The acknowledgment field (ti_ack) equals the largest unacknowledged
		 *			sequence number. This means no data is acknowledged by this segment.
		 *		3.	The reassembly list of out-of-order segments for the connection is empty
		 *			(seg_next equals tp).
		 *		4.	There is room in the receive buffer for the data in the segment.
		 */
		else if (ti->ti_ack() == tp->snd_una &&
			tp->seg_next == reinterpret_cast<struct tcpiphdr*>(tp) &&
			ti->ti_len() <= static_cast<short>(so->so_rcv.sbspace()))
		{
			/*
			 *	Complete processing of received data:
			 *	The next expected receive sequence number (rcv_nxt) is incremented by the number
			 *	of bytes of data. The IP header, TCP header, and any TCP options are dropped from
			 *	the mbuf, and the mbuf chain is appended to the socket's receive buffer. The receiving
			 *	process is awakened by sorwakeup. Notice that this code avoids calling the
			 *	TCP _REASS macro, since the tests performed by that macro have already been performed
			 *	by the header prediction tests. The delayed-ACK flag is set and the input processing
			 *	is complete.
			 *
			* this is a pure, in-sequence data packet
			* with nothing on the reassembly queue and
			* we have enough buffer space to take it.
			*/
			tp->rcv_nxt += ti->ti_len();

			/*
			* Drop TCP, IP headers and TCP options then add data
			* to socket buffer.
			*/
			auto view = boost::make_iterator_range(it + (sizeof(struct tcpiphdr) + off - sizeof(struct tcphdr)), m->end());
			so->so_rcv.sbappends(view);
			so->sorwakeup();
			tp->t_flags |= tcpcb::TF_DELACK;
			return;
		}
	}

	/*
	 *	TCP Input: Slow Path Processing:
	 *	We continue with the code that's executed if header prediction fails, the slow path
	 *	through tcp_input. Figure 28.14 shows the next piece of code, which prepares the
	 *	received segment for input processing.
	 *
	 *	Drop IP and TCP headers, Including TCP options:
	 *	The data pointer and length of the first mbuf in the chain are updated to skip over
	 *	the IP header, TCP header, and any TCP options. Since off is the number of bytes in
	 *	the TCP header, including options, the size of the normal TCP header (20) must be subtracted
	 *	from the expression.
	 *
	* Drop TCP, IP headers and TCP options.
	*/
	it += sizeof(struct tcpiphdr) + off - sizeof(struct tcphdr);

	/*
	 *	Calculate receive window
	 *	win is set to the number of bytes available in the socket's receive buffer.
	 *	rcv_adv - rcv_nxt is the current advertised window.
	 *	The receive window is the maximum of these two values.
	 *	The max is taken to ensure that the value is not less than the currently advertised window.
	 *	Also, if the process has taken data out of the socket receive buffer since the window was
	 *	last advertised, win could exceed the advertised window, so TCP accepts up to win
	 *	bytes of data (even though the other end should not be sending more than the advertised window).
	 *	This value is calculated now, since the code later in this function must determine
	 *	how much of the received data (if any) fits within the advertised window. Any received
	 *	data outside the advertised window is dropped: data to the left of the window is duplicate
	 *	data that has already been received and acknowledged, and data to the right	should not be sent
	 *	by the other end.
	 *
	* Calculate amount of space in receive window,
	* and then do TCP input processing.
	* Receive window is amount of space in rcv queue,
	* but not less than advertised window.
	*/
	{
		int win(so->so_rcv.sbspace());
		if (win < 0)
			win = 0;
		tp->rcv_wnd = std::max(win, static_cast<int>(tp->rcv_adv - tp->rcv_nxt));
	}

	int needoutput(0);
	switch (tp->t_state) {

		/*	Now we show the processing when the connection is in the LISTEN state. In this
		 *	code the variables tp and inp refer to the new socket that was created in Figure 28.7,
		 *	not the server's listening socket.
		 *
		* If the state is LISTEN then ignore segment if it contains a RST.
		* If the segment contains an ACK then it is bad and send a RST.
		* If it does not contain a SYN then it is not interesting; drop it.
		* Don't bother responding if the destination was a broadcast.
		* Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
		* tp->iss, and send a segment:
		*     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
		* Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
		* Fill in remote peer address fields if not previously specified.
		* Enter SYN_RECEIVED state, and process any other fields of this
		* segment in this state.
		*/
	case tcpcb::TCPS_LISTEN: {

		/*
		 *	Drop if RST, ACK, or no SYN
		 *	If the received segment contains the RST flag, it is dropped.
		 *	If it contains an ACK, it is dropped and an RST is sent as the reply.
		 *	(The initial SYN to open a connection is one of the few segments that
		 *	does not contain an ACK.)
		 *	If the SYN flag is not set, the segment is dropped.
		 *	The remaining code for this case handles the reception of a SYN for
		 *	a connection in the LISTEN state. The new state will be SYN_RCVD.
		 */
		if (tiflags & tcphdr::TH_RST)
			return drop(tp, dropsocket);
		else if (tiflags & tcphdr::TH_ACK)
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
		else if ((tiflags & tcphdr::TH_SYN) == 0)
			return drop(tp, dropsocket);

		/*
		 *	Get mbuf for client's IP address and port:
		 *	An mbuf is allocated to hold a sockaddr_in structure, and the structure is filled in
		 *	with the client's IP address and port number. The IP address is copied from the source
		 *	address in the IP header and the port number is copied from the source port number in
		 *	the TCP header. This structure is used shortly to connect the server's PCB to the client,
		 *	and then the mbuf is released.
		 *	The XXX comment is probably because of the cost associated with obtaining an mbuf just for
		 *	the call to in_pcbconnect that follows. But this is the slow processing path for TCP input.
		 *	Figure 24.5 shows that less than 2% of all received segments execute this code.
		 */
		struct sockaddr_in sin;
		size_t sin_len(sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = ti->ti_src();
		sin.sin_port = ti->ti_sport();
		std::memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

		/*
		 *	Set local address In PCB:
		 *	laddr is the local address bound to the socket. If the server bound the wildcard
		 *	address to the socket (the normal scenario), the destination address from the IP header
		 *	becomes the local address in the PCB. Note that the destination address from the IP
		 *	header is used, regardless of which local interface the datagram was received on.
		 *		Notice that laddr cannot be the wildcard address, because in Figure 28.7 it is explicitly set to
		 *		the destination IP address from the received datagram.
		 */
		const struct in_addr laddr(tp->inp_laddr());
		if (tp->inp_laddr().s_addr == INADDR_ANY)
			tp->inp_laddr() = ti->ti_dst();

		/*
		 *	Connect PCB to peer:
		 *	in_pcbconnect connects the server's PCB to the client. This fills in the foreign
		 *	address and foreign process in the PCB.
		 */
		if (tp->in_pcbconnect(&sin, sin_len)) {
			tp->inp_laddr() = laddr;
			return drop(tp, dropsocket);
		}

		/*	Allocate and initialize IP and TCP header template
		 *	A template of the IP and TCP headers is created by tcp_template. The call to
		 *	sonewconn in Figure 28.7 allocated the PCB and TCP control block for the new connection,
		 *	but not the header template.
		 */
		tp->tcp_template();
		if (tp->t_template == nullptr) {
			tcp_drop(*tp, ENOBUFS);
			/* socket is already gone */
			return drop(tp, 0);
		}

		/*
		 *	Process any TCP options:
		 *	If TCP options are present, they are processed by tcp_dooptions. The call to this
		 *	function in Figure 28.8 was done only if the connection was not in the LISTEN state.
		 *	This function is called now for a listening socket, after the foreign address is set in the
		 *	PCB, since the foreign address is used by the tcp_mss function: to get a route to the
		 *	peer, and to check if the peer is "local" or "foreign" (with regard to the peer's network
		 *	ID and subnet ID, used to select the MSS).
		 */
		if (optp)
			tcp_dooptions(*tp, optp, optlen, *ti, ts_present, ts_val, ts_ecr);

		/*
		 *	Initialize ISS:
		 *	The initial send sequence number is normally copied from the global tcp_iss,
		 *	which is then incremented by 64,000 (TCP ISSINCR divided by 2). If the local variable
		 *	iss is nonzero, however, its value is used instead of tcp_iss to initialize the send
		 *	sequence number for the connection.
		 *	The local iss variable is used for the following scenario.
		 *		a.	A server is started on port 27 on the host with an IP address of 128.1.2.3.
		 *		b.	A client on host 192.3.4.5 establishes a connection with this server. The client's
		 *			ephemeral port is 3000. The socket pair on the server is {128.1.2.3, 27, 192.3.4.5, 3000}.
		 *		c.	The server actively closes the connection, putting this socket pair into the
		 *			TIME_ WAIT state. While the connection is in this state, the last receive sequence
		 *			number is remembered in the TCP control block. Assume its value is 100,000.
		 *		d.	Before this connection leaves the TIME_WAIT state, a new SYN is received from
		 *			the same port on the same client host (192.3.4.5, port 3000), which locates the
		 *			PCB corresponding to the connection in the TIME_WAIT state, not the PCB for
		 *			the listening server. Assume the sequence number of this new SYN is 200,000.
		 *		e.	Since this connection does not correspond to a listening socket in the LISTEN
		 *			state, the code we just looked at is not executed. Instead, the code in Figure
		 *			28.29 is executed, and we'll see that it contains the following logic: if the
		 *			sequence number of the new SYN (200,000) is greater than the last sequence
		 *			number received from this client (100,000), then
		 *				(1)	the local variable iss is set to 100,000 plus 128,000,
		 *				(2) the connection in the TIME_ WAIT state is completely closed
		 *					(its PCB and TCP control block are deleted), and
		 *				(3) a jump is made to findpcb (Figure 28.5).
		 *		f.	This time the server's listening PCB will be located (assuming the listening
		 *			server is still running), causing the code in this section to be executed. The local
		 *			variable iss (now 228,000) is used in Figure 28.17 to initialize tcp_iss for the
		 *			new connection.
		 *	This logic, which is allowed by RFC 1122, lets the same client and server reuse the same
		 *	socket pair as long as the server does the active close. This also explains why the global
		 *	variable tcp_iss is incremented by 64,000 each time any process issues a connect
		 *	(Figure 30.4): to ensure that if a single client reopens the same connection with the same
		 *	server repeatedly, a larger ISS is used each time, even if no data was transferred on the
		 *	previous connection, and even if the 500-ms timer (which increments tcp_iss) has not
		 *	expired since the last connection.
		 */
		tp->iss = iss ? iss : tcp_iss;
		TCP_ISSINCR();

		/*
		 *	Initialize sequence number variables In control block:
		 *	In Figure 28.17, the initial receive sequence number (irs) is copied from the
		 *	sequence number in the SYN segment. The following two macros initialize the appropriate
		 *	variables in the TCP control block:
		 *		inline void tcp_rcvseqinit() {rcv_adv = rcv_nxt = irs + 1; }
		 *		inline void tcp_sendseqinic() {snd_una = snd_nxt = snd_max = snd_up = iss; }
		 *	The addition of 1 in the first inline is because the SYN occupies a sequence number.
		 */
		tp->irs = ti->ti_seq();
		tp->tcp_sendseqinit();
		tp->tcp_rcvseqinit();

		/*
		 *	ACK the SYN and change state
		 *	The TF_ACKNOW flag is set since the ACK of a SYN is not delayed. The connection
		 *	state becomes TCPS_SYN_RECEIVED, and the connection-establishment timer is set to 75 seconds
		 *	(TCPTV_KEEP_INIT). Since the TF_ACKNOW flag is set, at the bottom of this function
		 *	tcp_output will be called. Looking at Figure 24.16 we see that tcp_outflags will
		 *	cause a segment with the SYN and ACK flags to be sent.
		 */
		tp->t_flags |= tcpcb::TF_ACKNOW;
		tp->t_state = tcpcb::TCPS_SYN_RECEIVED;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;

		/*
		 *	TCP is now committed to the new socket created in Figure 28.7, so the dropsocket
		 *	flag is cleared. The code at trimthenstep6 is jumped to, to complete processing of
		 *	the SYN segment. Remember that a SYN segment can contain data, although the data
		 *	cannot be passed to the application until the connection enters the ESTABLISHED state.
		 */
		dropsocket = 0;		/* committed to socket */
		return trimthenstep6(tp, tiflags, ti, m, it, tiwin, needoutput);
	}

								   /*
									*	Completion of Active Open:
									*	the first part of processing when the connection is in the SYN_SENT state. TCP is expecting to receive a SYN.
								   * If the state is SYN_SENT:
								   *	if seg contains an ACK, but not for our SYN, drop the input.
								   *	if seg contains a RST, then drop the connection.
								   *	if seg does not contain SYN, then drop it.
								   * Otherwise this is an acceptable SYN segment
								   *	initialize tp->rcv_nxt and tp->irs
								   *	if seg contains ack then advance tp->snd_una
								   *	if SYN has been acked change to ESTABLISHED else SYN_RCVD state
								   *	arrange for segment to be acked (eventually)
								   *	continue processing rest of data/controls, beginning with URG
								   */
	case tcpcb::TCPS_SYN_SENT:

		/*
		 *	Verify received ACK:
		 *	When TCP sends a SYN in response to an active open by a process, we'll see in Figure
		 *	30.4 that the connection's iss is copied from the global tcp_iss and the inline
		 *	tcp_sendseqinit (shown at the end of the previous section) is executed.
		 *	For example, Assuming the ISS is 365, the send sequence variables after the SYN is sent by tcp_output:
		 *			SYN				366				367
		 *			 /\				 /\
		 *			 ||				 ||
		 *			snd_una = 365	snd_nxt = 366
		 *			snd_up = 365	snd_max = 366
		 *	Figure 28.19 Send variables after SYN is sent with sequence number 365.
		 *
		 *	tcp_sendseqinit sets all four of these variables to 365, then Figure 26.31 increments
		 *	two of them to 366 when the SYN segment is output. Therefore, if the received
		 *	segment in Figure 28.18 contains an ACK, and if the acknowledgment field is less than
		 *	or equal to iss (365) or greater than snd_max (366), the ACK is invalid, causing the
		 *	segment to be dropped and an RST sent in reply. Notice that the received segment for a
		 *	connection in the SYN_SENT state need not contain an ACK. It can contain only a SYN,
		 *	which is called a simultaneous open (Figure 24.15), and is described shortly.
		 */
		if ((tiflags & tcphdr::TH_ACK) &&
			(tcpcb::SEQ_LEQ(ti->ti_ack(), tp->iss) || tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max)))
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);

		/*
		 *	Process and drop RST segment:
		 *	If the received segment contains an RST, it is dropped. But the ACK flag was
		 *	checked first because receipt of an acceptable ACK (which was just verified) and an RST
		 *	in response to a SYN is how the other end tells TCP that its connection request was
		 *	refused. Normally this is caused by the server process not being started on the other
		 *	host. In this case tcp_drop sets the socket's so_error variable, causing an error to be
		 *	returned to the process that called connect.
		 */
		if (tiflags & tcphdr::TH_RST)
			if (tiflags & tcphdr::TH_ACK)
				tcp_drop(*tp, ECONNREFUSED);
			else
				return drop(tp, dropsocket);

		/*
		 *	Verify SYN flag set:
		 *	If the SYN flag is not set in the received segment, it is dropped.
		 */
		if ((tiflags & tcphdr::TH_SYN) == 0)
			return drop(tp, dropsocket);

		/*
		 *	The remainder of this case handles the receipt of a SYN (with an optional ACK) in
		 *	response to TCP's SYN. The next part of tcp_input, shown in Figure 28.20, continues
		 *	processing the SYN.
		 *
		 *	Process ACK:
		 *	If the received segment contains an ACK, snd_una is set to the acknowledgment
		 *	field. In Figure 28.19, snd_una becomes 366, since 366 is the only acceptable value for
		 *	the acknowledgment field. If snd_nxt is less than snd_una (which shouldn't happen,
		 *	given Figure 28.19), snd_nxt is set to snd_una.
		 */
		if (tiflags & tcphdr::TH_ACK) {
			tp->snd_una = ti->ti_ack();
			if (tcpcb::SEQ_LT(tp->snd_nxt, tp->snd_una))
				tp->snd_nxt = tp->snd_una;
		}

		/*
		 *	Tum off retransmission timer:
		 *	The retransmission timer is turned off.
		 *		This is a bug. This timer should be turned off only if the ACK flag is set, since the receipt of a
		 *		SYN without an ACK is a simultaneous open, and doesn't mean the other end received TCP's
		 *		SYN.
		 */
		tp->t_timer[TCPT_REXMT] = 0;

		/*
		 *	Initialize receive sequence numbers:
		 *	The initial receive sequence number is copied from the sequence number of the
		 *	received segment. The tcp_rcvseqini t macro (shown at the end of the previous section)
		 *	initializes rcv_adv and rcv_nxt to the receive sequence number, plus 1. The
		 *	TF ACKNOW flag is set, causing tcp_output to be called at the bottom of this function.
		 *	The segment it sends will contain rcv_nxt as the acknowledgment field (Figure 26.27),
		 *	which acknowledges the SYN just received.
		 */
		tp->irs = ti->ti_seq();
		tp->tcp_rcvseqinit();
		tp->t_flags |= tcpcb::TF_ACKNOW;

		/*
		 *	If the received segment contains an ACK, and if snd_una is greater than the ISS for
		 *	the connection, the active open is complete, and the connection is established.
		 *	This second test appears superfluous. At the beginning of Figure 28.20 snd_una was set to the
		 *	received acknowledgment field if the ACK flag was on. Also the if following the case
		 *	statement in Figure 28.18 verified that the received acknowledgment field is greater than the
		 *	ISS. So at this point in the code, if the ACK flag is set, we're already guaranteed that snd_una
		 *	is greater than the ISS.
		 */
		if (tiflags & tcphdr::TH_ACK && tcpcb::SEQ_GT(tp->snd_una, tp->iss)) {

			/*
			 *	Connection Is established:
			 *	soisconnected sets the socket state to connected, and the state of the TCP connection
			 *	is set to ESTABLISHED.
			 */
			so->soisconnected();
			tp->t_state = tcpcb::TCPS_ESTABLISHED;

			/*
			 * Check for window scale option:
			 * If TCP sent the window scale option in its SYN and the received SYN also contains
			 * the option, the option is enabled and the two variables snd_scale and rcv_scale are
			 * set. Since the TCP control block is initialized to 0 by tcp_newtcpcb, these two variables
			 * correctly default to 0 if the window scale option is not used.
			 *
			 * Do window scaling on this connection?
			 */
			if ((tp->t_flags & (tcpcb::TF_RCVD_SCALE | tcpcb::TF_REQ_SCALE)) ==
				(tcpcb::TF_RCVD_SCALE | tcpcb::TF_REQ_SCALE))
			{
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}

			/*
			 *	Pass any queued data to process:
			 *	Since data can arrive for a connection before the connection is established, any such
			 *	data is now placed in the receive buffer by calling tcp_reass with a null pointer as the
			 *	second argument.
			 *		Remark: This test is unnecessary. In this piece of code, TCP has just received the SYN with an ACK that
			 *				moves it from the SYN_SENT state to the ESTABLISHED state. If data appears with this
			 *				received SYN segment, it isn't processed until the label dodata near the end of the function. If
			 *				TCP just received a SYN without an ACK (a simultaneous open) but with some data, that data
			 *				is handled later (Figure 29.2) when the ACK is received that moves the connection from the
			 *				SYN_RCVD state to the ESTABLISHED state.
			 *				Although it is valid for data to accompany a SYN, and Net/3 handles this type of received segment
			 *				correctly, Net/3 never generates such a segment.
			 */
			(void)tcp_reass(tp, nullptr, nullptr, std::vector<byte>::iterator());

			/*
			 *	Update RTT estimators:
			 *	If the SYN that is ACKed was being timed, tcp_xrnit_timer initializes the RIT
			 *	estimators based on the measured RTT for the SYN.
			 *		Remark:	TCP ignores a received timestamp option here, and checks only the t_rtt counter. TCP sends
			 *				a timestamp in a SYN generated by an active open (Figure 26.24) and if the other end agrees to
			 *				the option, the other end should echo the received timestamp in its SYN. (Net/3 echoes the
			 *				received timestamp in a SYN in Figure 28.10.) This would allow TCP to use the received timestamp
			 *				here, instead of t_rtt, but since both have the same precision (500 ms) there's no
			 *				advantage in using the timestamp value. The real advantage in using the timestamp option,
			 *				instead of the t_rtt counter, is with large pipes, when lots of segments are in flight at once,
			 *				providing more RTT timings and (it is hoped) better estimators.
			 *
			* if we didn't have to retransmit the SYN,
			* use its rtt as our initial srtt & rtt var.
			*/
			if (tp->t_rtt)
				tp->tcp_xmit_timer(tp->t_rtt);
		}

		/*
		 *	Simultaneous open:
		 *	When TCP receives a SYN without an ACK in the SYN_SENT state, it is a simultaneous
		 *	open and the connection moves to the SYN_RCVD state.
		 */
		else
			tp->t_state = tcpcb::TCPS_SYN_RECEIVED;

		return trimthenstep6(tp, tiflags, ti, m, it, tiwin, needoutput);
	}

	/*
	 *	PAWS: Protection Against Wrapped Sequence Numbers:
	 *	The next part of tcp_input, shown in Figure 28.22, provides protection against
	 *	wrapped sequence numbers: the PAWS algorithm from RFC 1323. Also recall our discussion
	 *	of the timestamp option in Section 26.6.
	 *
	 *	Basic PAWS test:
	 *	ts_present was set by tcp_dooptions if a timestamp option was present. If
	 *	the following three conditions are all true, the segment is dropped:
	 *		1.	the RST flag is not set (Exercise 28.8),
	 *		2.	TCP has received a valid timestamp from this peer (ts_recent is nonzero), and
	 *		3.	the received timestamp in this segment (ts_val) is less than the previously
	 *			received timestamp from this peer.
	 *	PAWS is built on the premise that the 32-bit timestamp values wrap around at a much
	 *	lower frequency than the 32-bit sequence numbers, on a high-speed connection. Exercise
	 *	28.6 shows that even at the highest possible timestamp counter frequency (incrementing
	 *	by 1 bit every millisecond), the sign bit of the timestamp wraps around only
	 *	every 24 days. On a high-speed network such as a gigabit network, the sequence
	 *	number can wrap in 17 seconds (Section 24.3 of Volume 1). Therefore, if the received
	 *	timestamp value is less than the most recent one from this peer, this segment is old and
	 *	must be discarded (subject to the outdated timestamp test that follows). The packet
	 *	might be discarded later in the input processing because the sequence number is "old,"
	 *	but PAWS is intended for high-speed connections where the sequence numbers can
	 *	wrap quickly.
	 *	Notice that the PAWS algorithm is symmetric: it not only discards duplicate data
	 *	segments but also discards duplicate ACKs. All received segments are subject to PAWS.
	 *	Recall that the header prediction code also applied the PAWS test (Figure 28.11).
	 *
	* States other than LISTEN or SYN_SENT.
	* First check timestamp, if present.
	* Then check that at least some bytes of segment are within
	* receive window.  If segment begins before rcv_nxt,
	* drop leading data (and SYN); if nothing left, just ack.
	*
	* RFC 1323 PAWS: If we have a timestamp reply on this segment
	* and it's less than ts_recent, drop it.
	*/
	if (ts_present &&
		(tiflags & tcphdr::TH_RST) == 0 &&
		tp->ts_recent &&
		TSTMP_LT(ts_val, tp->ts_recent))

		/*
		 *	Check for outdated timestamp:
		 *	There is a small possibility that the reason the PAWS test fails is because the connection
		 *	has been idle for a long time. The received segment is not a duplicate; it is just that
		 *	because the connection has been idle for so long, the peer's timestamp value has
		 *	wrapped around when compared to the most recent timestamp from that peer.
		 *	Whenever ts_recent is copied from the timestamp in a received segment,
		 *	ts_recent_age records the current time (tcp_now). If the time at which ts_recent
		 *	was saved is more than 24 days ago, it is set to 0 to invalidate it. The constant
		 *	TCP_PAWS_IDLE is defined to be (24 x 24 x 60 x 60 x 2), the final 2 being the number of
		 *	ticks per second. The received segment is not dropped in this case, since the problem is
		 *	not a duplicated segment, but an outdated timestamp. See also Exercises 28.6 and 28.7.
		 *	Figure 28.23 shows an example of an outdated timestamp. The system on the left is
		 *	a non-Net/3 system that increments its timestamp clock at the highest frequency
		 *	allowed by RFC 1323: once every millisecond. The system on the right is a Net/3 system.
		 *					data, timestamp = 1
		 *	timestamp = 1	----------------------------------------->		\ts_recent = ts_val = 1
		 *					<-----------------------------------------		/ts_recent_age = tcp_now = N
		 *							ACK										\
		 *																	|
		 *																	|	connection idle
		 *																	 >	for 25 days =
		 *	timestamp = 2,147,483,649	\	timestamp						|	4,320,000 ticb
		 *	timestamp = 2,147,483,650	/	changes sign					|
		 *																	/
		 *								data, timestamp = 2,160,000,001		\	ts_ val= 2,160,000,001
		 *	timestamp = 2,160,000,001	------------------------------>		 >			< ts_recent = l
		 *																	/	tcp_now = N + 4,320,000
		 *	Figure 28.23 Example of outdated timestamp.
		 *
		 *	When the data segment arrives with a timestamp of 1, that value is saved in
		 *	ts_recent and ts_recent_age is set to the current time (tcp_now), as shown in
		 *	Figures 28.11 and 28.35. The connection is then idle for 25 days, during which time
		 *	tcp_now will increase by 4,320,000 (25 x 24 x 60 x 60 x 2). During these 25 days the
		 *	other end's timestamp clock will increase by 2,160,000,000 (25 x 24 x 60 x 60 x 1000).
		 *	During this interval the timestamp "changes sign" with regard to the value 1, that is,
		 *	2,147,483,649 is greater than 1, but 2,147,483,650 is less than 1 (recall Figure 24.26).
		 *	Therefore, when the data segment is received with a timestamp of 2,160,000,001, this
		 *	value is less than ts_recent (1), when compared using the TSTMP_LT macro, so the
		 *	PAWS test fails. But since tcp_now minus ts_recent_age is greater than 24 days, the
		 *	reason for the failure is that the connection has been idle for more than 24 days, and the
		 *	segment is accepted.
		 *
		 * Check to see if ts_recent is over 24 days old.  */
		if (static_cast<int>(tcp_now - tp->ts_recent_age) > TCP_PAWS_IDLE)

			/*
			* Invalidate ts_recent.  If this segment updates
			* ts_recent, the age will be reset later and ts_recent
			* will get a valid value.  If it does not, setting
			* ts_recent to zero will at least satisfy the
			* requirement that zero be placed in the timestamp
			* echo reply when ts_recent isn't valid.  The
			* age isn't reset until we get a valid ts_recent
			* because we don't want out-of-order segments to be
			* dropped when ts_recent is old.
			*/
			tp->ts_recent = 0;
		else

			/*
			 *	Drop duplicate segment:
			 *	The segment is determined to be a duplicate based on the PAWS algorithm, and the
			 *	timestamp is not outdated. It is dropped, after being acknowledged (since all duplicate
			 *	segments are acknowledged).
			 *		Remark:	Figure 24.S shows a much smaller value for tcps_pawsdrop (22) than for
			 *				tcps_rcvduppack (46,953). This is probably because fewer systems support the timestamp
			 *				option today, causing most duplicate packets to be discarded by later tests in TCP's input processing
			 *				instead of by PAWS.
			 */
			return dropafterack(tp, dropsocket, tiflags);

	/*
	 *	Trim Segment so Data Is Within Window:
	 *	This section trims the received segment so that it contains only data that is within the
	 *	advertised window:
	 *		a.	duplicate data at the beginning of the received segment is discarded, and
	 *		b.	data that is beyond the end of the window is discarded from the end of the segment.
	 *	What remains is new data within the window. The code shown in Figure 28.24 checks if
	 *	there is any duplicate data at the beginning of the segment.
	 *
	 *	Check If any duplicate data at front of segment:
	 *	If the starting sequence number of the received segment (ti_seq) is less than the
	 *	next receive sequence number expected (rcv_nxt), data at the beginning of the segment
	 *	is old and todrop will be greater than 0. These data bytes have already been
	 *	acknowledged and passed to the application (Figure 24.18).
	 */
	int todrop(tp->rcv_nxt - ti->ti_seq());
	if (todrop > 0) {

		/*
		 *	Remove duplicate SYN:
		 *	If the SYN flag is set, it refers to the first sequence number in the segment, which is
		 *	known to be old. The SYN flag is cleared and the starting sequence number of the segment
		 *	is incremented by 1 to skip over the duplicate SYN. Furthermore, if the urgent offset
		 *	in the received segment (ti_urp) is greater than 1, it must be decremented by 1,
		 *	since the urgent offset is relative to the starting sequence number, which was just incremented.
		 *	If the urgent offset is 0 or 1, it is left alone, but in case it was 1, the URG flag is
		 *	cleared. Finally todrop is decremented by 1 (since the SYN occupies a sequence number).
		 *	The handling of duplicate data at the front of the segment continues in Figure 28.25.
		 */
		if (tiflags & tcphdr::TH_SYN)
		{
			tiflags &= ~tcphdr::TH_SYN;
			ti->ti_seq()++;
			if (ti->ti_urp() > 1)
				ti->ti_urp()--;
			else
				tiflags &= ~tcphdr::TH_URG;
			todrop--;
		}

#ifdef FIXBUG_959

		/*
		*	When to Drop an ACK:
		*	The code in Figure 28.25 has a bug that causes a jump to dropafterack in several
		*	cases when the code should fall through for further processing of the segment [Carlson
		*	1993; Lanciani 1993). In an actual scenario, when both ends of a connection had a hole
		*	in the data on the reassembly queue and both ends enter the persist state, the connection
		*	becomes deadlocked as both ends throw away perfectly good ACKs.
		*	The fix is to simplify the code at the beginning of Figure 28.25. Instead of jumping
		*	to dropafterack, a completely duplicate segment causes the FIN flag to be turned off
		*	and an immediate ACK to be generated at the end of the function. Lines 646-676 in
		*	Figure 28.25 are replaced with the code shown in Figure 28.30. This code also corrects
		*	another bug present in the original code (Exercise 28.9).
		*/
		if (todrop > ti->ti_len() ||
			todrop == ti->ti_len() && (tiflags & tcphdr::TH_FIN) == 0) {

			/*
			* Any valid FIN must be to the left of the window.
			* At this point the FIN must be a duplicate or
			* out of sequence; drop it.
			*/
			tiflags &= ~tcphdr::TH_FIN;

			/*
			* Send an ACK to resynchronize and drop any data.
			* But keep on processing for RST or ACK.
			*/
			tp->t_flags |= tcpcb::TF_ACKNOW;
			todrop = ti->ti_len();
		}
#else
		/*
		*	Check for entire duplicate packet:
		*	If the amount of duplicate data at the front of the segment is greater than or equal to
		*	the size of the segment, the entire segment is a duplicate.
		*/
		if (todrop >= ti->ti_len()) {

			/*
			*	Check for duplicate FIN:
			*	The next check is whether the FIN is duplicated. Figure 28.26 shows an example of
			*	this.
			*	In this example todrop equals 5, which is greater than or equal to ti_len (4). Since
			*	the FIN flag is set and todrop equals ti_len plus 1, todrop is set to 4, the FIN flag is
			*	cleared, and the T_ ACKNOW flag is set, forcing an immediate ACK to be sent at the end
			*	of this function. This example also works for other segments if ti_seq plus ti_len
			*	equals 10.
			*		Remark:	The code contains the comment regarding 4.2850 keepalives. This code (another test within
			*				the if statement) is omitted.
			*
			* If segment is just one to the left of the window,
			* check two special cases:
			* 1. Don't toss RST in response to 4.2-style keepalive.
			* 2. If the only thing to drop is a FIN, we can drop
			*    it, but check the ACK or we will get into FIN
			*    wars if our FINs crossed (both CLOSING).
			* In either case, send ACK to resynchronize,
			* but keep on processing for RST or ACK.
			*/
			if ((tiflags & tcphdr::TH_FIN && todrop == ti->ti_len() + 1)
#ifdef TCP_COMPAT_42
				|| (tiflags & tcphdr::TH_RST && ti->ti_seq() == tp->rcv_nxt - 1)
#endif
				) {
				todrop = ti->ti_len();
				tiflags &= ~tcphdr::TH_FIN;
			}

			/*
			 *	Generate duplicate ACK:
			 *	If todrop is nonzero (the completely duplicate segment contains data) or the ACK
			 *	flag is not set, the segment is dropped and an ACK is generated by dropafterack.
			 *	This normally occurs when the other end did not receive our ACK, causing the other
			 *	end to retransmit the segment. TCP generates another ACK.
			 *
			 *	Handle simultaneous open or self-connect:
			 *	This code also handles either a simultaneous open or a socket that connects to itself.
			 *	We go over both of these scenarios in the next section. If todrop equals 0 (there is no
			 *	data in the completely duplicate segment) and the ACK flag is set, processing is allowed
			 *	to continue.
			 *		Remark:	This if statement is new with 4.4BSD. Earlier Berkeley-derived systems just had a jump to
			 *				dropafterack. These systems could not handle either a simultaneous open or a socket connecting to itself.
			 *				Nevertheless, the piece of code in this figure still has bugs, which we describe at the end of this section.
			 *
			 * Handle the case when a bound socket connects
			 * to itself. Allow packets with a SYN and
			 * an ACK to continue with the processing.
			 */
			else if (todrop != 0 || (tiflags & tcphdr::TH_ACK) == 0)
				return dropafterack(tp, dropsocket, tiflags);
		}
		tp->t_flags |= tcpcb::TF_ACKNOW;
#endif

		/*
		 *	Remove duplicate data and update urgent offset:
		 *	The duplicate bytes are removed from the front of the mbuf chain by m_adj and the
		 *	starting sequence number and length adjusted appropriately. If the urgent offset points
		 *	to data still in the mbuf, it is also adjusted. Otherwise the urgent offset is set to 0 and
		 *	the URG flag is cleared.
		 */
		std::move(it + todrop, m->end(), it);
		m->resize(m->size() - todrop);
		ti->ti_seq() += todrop;
		ti->ti_len() -= todrop;
		if (ti->ti_urp() > todrop)
			ti->ti_urp() -= todrop;
		else {
			tiflags &= ~tcphdr::TH_URG;
			ti->ti_urp() = 0;
		}
	}

	/*
	 *	The next part of input processing handles data that arrives after the process has terminated.
	 *
	 *	If the socket has no descriptor referencing it, the process has closed the connection
	 *	(the state is any one of the five with a value greater than CLOSE_WAIT in Figure 24.16),
	 *	and there is data in the received segment, the connection is closed. The segment is then
	 *	dropped and an RST is output.
	 *	Because of TCP's half-close, if a process terminates unexpectedly (perhaps it is terminated
	 *	by a signal), when the kernel closes all open descriptors as part of process termination,
	 *	a FIN is output by TCP. The connection moves into the FIN_WAIT_l state.
	 *	But the receipt of the FIN by the other end doesn't tell TCP whether this end performed
	 *	a half-close or a full-close. If the other end assumes a half-close, and sends more data, it
	 *	will receive an RST from the code in Figure 28.27.
	 *
	* If new data are received on a connection after the
	* user processes are gone, then RST the other end.
	*/
	if ((so->so_state & socket::SS_NOFDREF) &&
		tp->t_state > tcpcb::TCPS_CLOSE_WAIT && ti->ti_len())
	{
		(void)tcp_close(*tp);
		return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
	}

	/*
	 *	The next piece of code removes any data from the end of the
	 *	received segment that is beyond the right edge of the advertised window.
	 *
	 *	Calculate number of bytes beyond right edge of window:
	 *	todrop contains the number of bytes of data beyond the right edge of the window.
	 *	For example, in Figure 28.28, todrop would be (6 + 5) minus (4 + 6), or 1.
	 *
	* If segment ends after window, drop trailing data
	* (and PUSH and FIN); if nothing left, just ACK.
	*/
	if ((todrop = (ti->ti_seq() + ti->ti_len()) - (tp->rcv_nxt + tp->rcv_wnd)) > 0) {
		if (todrop >= ti->ti_len())

			/*
			*	Check for new Incarnation of a connection in the TIME_WAIT state:
			*	If todrop is greater than or equal to the length of the segment, the entire segment
			*	will be dropped. If the following three conditions are all true:
			*		1.	the SYN flag is set, and
			*		2.	the connection is in the TIME_ WAIT state, and
			*		3.	the new starting sequence number is greater than the final sequence number for
			*			the connection,
			*	this is a request for a new incarnation of a connection that was recently terminated and
			*	is currently in the TIME_WAIT state. This is allowed by RFC 1122, but the ISS for the
			*	new connection must be greater than the last sequence number used (rcv_nxt). TCP
			*	adds 128,000 (TCP_ISSINCR), which becomes the ISS when the code in Figure 28.17 is
			*	executed. The PCB and TCP control block for the connection in the TIME_WAIT state is
			*	discarded by tcp_close. A jump is made to findpcb (Figure 28.5) to locate the PCB
			*	for the listening server, assuming it is still running. The code in Figure 28.7 is then executed,
			*	creating a new socket for the new connection, and finally the code in Figures
			*	28.16 and 28.17 will complete the new connection request.
			*
			* If a new connection request is received
			* while in TIME_WAIT, drop the old connection
			* and start over if the sequence numbers
			* are above the previous ones.
			*/
			if (tiflags & tcphdr::TH_SYN &&
				tp->t_state == tcpcb::TCPS_TIME_WAIT &&
				tcpcb::SEQ_GT(ti->ti_seq(), tp->rcv_nxt))
			{
				iss = tp->snd_nxt;
				TCP_ISSINCR();
				(void)tcp_close(*tp);
				goto findpcb;
			}

		/*
		*	Check for probe of closed window:
		*	If the receive window is closed (rcv_wnd equals 0) and the received segment starts
		*	at the left edge of the window (rcv_nxt), then the other end is probing TCP's closed
		*	window. An immediate ACK is sent as the reply, even though the ACK may still advertise
		*	a window of 0. Processing of the received segment also continues for this case.
		*
		* If window is closed can only take segments at
		* window edge, and have to drop data and PUSH from
		* incoming segments.  Continue processing, but
		* remember to ack.  Otherwise, drop segment
		* and ack.
		*/
			else if (tp->rcv_wnd == 0 && ti->ti_seq() == tp->rcv_nxt)
				tp->t_flags |= tcpcb::TF_ACKNOW;
			else

				/*
				*	Drop other segments that are completely outside window
				*	The entire segment lies outside the window and it is not a window probe, so the
				*	segment is discarded and an ACK is sent as the reply. This ACK will contain the
				*	expected sequence number.
				*/
				return dropafterack(tp, dropsocket, tiflags);

		/*
		 *	Handle segments that contain some valid data:
		 *	The data to the right of the window is discarded from the mbuf chain by m_adj and
		 *	ti_len is updated. In the case of a probe into a closed window, this discards all the
		 *	data in the mbuf chain and sets ti_len to 0. Finally the FIN and PSH flags are cleared.
		 */
		m->resize(m->size() - todrop);
		ti->ti_len() -= todrop;
		tiflags &= ~(tcphdr::TH_PUSH | tcphdr::TH_FIN);
	}

	/*
	 *	Record Timestamp:
	 *	The next part of tcp_input handles a received timestamp option.
	 *
	 *	If the received segment contains a timestamp, the timestamp value is saved in
	 *	ts_recent. We discussed in Section 26.6 how this code used by Net/3 is flawed.
	 *	The expression:
	 *					((tiflags & (TH_SYN || TH_FIN)) != 0)
	 *	is 0 if neither of the two flags is set, or 1 if either is set. This effectively adds 1 to
	 *	ti_len if either flag is set.
	 *
	* If last ACK falls within this segment's sequence numbers,
	* record its timestamp.
	*/
	if (ts_present && tcpcb::SEQ_LEQ(ti->ti_seq(), tp->last_ack_sent) &&
		tcpcb::SEQ_LT(tp->last_ack_sent, ti->ti_seq() + ti->ti_len() + ((tiflags & (tcphdr::TH_SYN | tcphdr::TH_FIN)) != 0)))
	{
		tp->ts_recent_age = tcp_now;
		tp->ts_recent = ts_val;
	}

	/*
	 *	RST Processing:
	 *	Figure 28.36 shows the switch statement to handle the RST flag, which depends on the
	 *	connection state.
	 *
	* If the RST bit is set examine the state:
	*    SYN_RECEIVED STATE:
	*	If passive open, return to LISTEN state.
	*	If active open, inform user that connection was refused.
	*    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	*	Inform user that connection was reset, and close tcb.
	*    CLOSING, LAST_ACK, TIME_WAIT STATES
	*	Close the tcb.
	*/
	if (tiflags & tcphdr::TH_RST)
		switch (tp->t_state) {

			/*
			 *	SYN_RCVD state:
			 *	The socket's error code is set to ECONNREFUSED, and a jump is made a few lines forward
			 *	to close the socket.
			 *	This state can be entered from two directions. Normally it is entered from the LISTEN state,
			 *	after a SYN has been received. TCP replied with a SYN and an ACK but received an RST in reply.
			 *	Perhaps the other end sent its SYN and then terminated before the reply arrived, causing it
			 *	to send an RST. In this case the socket referred to by so is the new socket created by sonewconn
			 *	in Figure 28.7. Since dropsocket will still be true, the socket is discarded at the label drop.
			 *	The listening descriptor isn't affected at all. This is why we show the state transition from
			 *	SYN_RCVD back to LISTEN in Figure 24.15.
			 *	This state can also be entered by a simultaneous open, after a process has called connect.
			 *	In this case the socket error is returned to the process.
			 */
		case tcpcb::TCPS_SYN_RECEIVED:
			so->so_error = ECONNREFUSED;
			tp->t_state = tcpcb::TCPS_CLOSED;
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);

			/*
			 *	Other states:
			 *	The receipt of an RST in the ESTABLISHED, FIN_WAIT_l, FIN_WAIT_2, or
			 *	CLOSE_WAIT states returns the error ECONNRESET. In the CLOSING, LAST_ACK, and
			 *	TIME_WAIT state an error is not generated, since the process has closed the socket.
			 *		Remark:	Allowing an RST to terminate a connection in the TIME_WAIT state circumvents the reason
			 *				this state exists. RFC 1337 [Braden 1992] discusses this and other forms of "TIME_WAIT
			 *				assassination hazards" and recommends not letting an RST prematurely terminate the TIME_WAIT
			 *				state. See Exercise 28.10 for an example.
			 */
		case tcpcb::TCPS_ESTABLISHED:
		case tcpcb::TCPS_FIN_WAIT_1:
		case tcpcb::TCPS_FIN_WAIT_2:
		case tcpcb::TCPS_CLOSE_WAIT:
			so->so_error = ECONNRESET;
			tp->t_state = tcpcb::TCPS_CLOSED;
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);

		case tcpcb::TCPS_CLOSING:
		case tcpcb::TCPS_LAST_ACK:
		case tcpcb::TCPS_TIME_WAIT:
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);
		}

	/*
	 *	The next piece of code checks for erroneous SYNs and verifies that an ACK is present.
	 *	If the SYN flag is still set, this is an error and the connection is dropped with the
	 *	error ECONNRESET.
	 *
	* If a SYN is in the window, then this is an
	* error and we send an RST and drop the connection.
	*/
	if (tiflags & tcphdr::TH_SYN) {
		tcp_drop(*tp, ECONNRESET);
		return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
	}

	/*
	 *	If the ACK flag is not set, the segment is dropped. The remainder of this function,
	 *	which we continue in the next chapter, assumes the ACK flag is set.
	 *
	* If the ACK bit is off we drop the segment and return.
	*/
	if ((tiflags & tcphdr::TH_ACK) == 0)
		return drop(tp, dropsocket);

	/*
	 *	ACK Processing Overview:
	 *	We begin this chapter with ACK processing, a summary of which is shown in Figure
	 *	29.1. The SYN_RCVD state is handled specially, followed by common processing
	 *	for all remaining states. (Remember that a received ACK in either the LISTEN or
	 *	SYN_SENT state was discussed in the previous chapter.) This is followed by special
	 *	processing for the three states in which a received ACK causes a state transition, and for
	 *	the TIME_WAIT state, in which the receipt of an ACK causes the 2MSL timer to be
	 *	restarted.
	 *
	 *
	 *	Completion of Passive Opens and Simultaneous Opens:
	 *	The first part of the ACK processing, shown in Figure 29.2, handles the SYN_RCVD
	 *	state. As mentioned in the previous chapter, this handles the completion of a passive
	 *	open (the common case) and also handles simultaneous opens and self-connects (the
	 *	infrequent case).
	 */
	std::vector<byte>::iterator tcpreass;
	switch (tp->t_state) {

		/*
		* In SYN_RECEIVED state if the ack ACKs our SYN then enter
		* ESTABLISHED state and continue processing, otherwise
		* send an RST.
		*/
	case tcpcb::TCPS_SYN_RECEIVED:

		/*
		 *	Verify received ACK:
		 *	For the ACK to acknowledge the SYN that was sent, it must be greater than
		 *	snd_una (which is set to the ISS for the colUlection, the sequence number of the SYN,
		 *	by tcp_sendseqinit) and less than or equal to snd_max. If so, the socket is marked
		 *	as connected and the state becomes ESTABLISHED.
		 *	Since soisconnected wakes up the process that performed the passive open (normally
		 *	a server), we see that this doesn't occur until the last of the three segments in the
		 *	three-way handshake has been received. If the server is blocked in a call to accept,
		 *	that call now returns; if the server is blocked in a call to select ·waiting for the listening
		 *	descriptor to become readable, it is now readable.
		 */
		if (tcpcb::SEQ_GT(tp->snd_una, ti->ti_ack()) || tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max))
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);

		so->soisconnected();
		tp->t_state = tcpcb::TCPS_ESTABLISHED;

		/*
		 *	Check for window scale option:
		 *	If TCP sent a window scale option and received one, the send and receive scale factors
		 *	are saved in the TCP control block. Otherwise the default values of snd_scale
		 *	and rcv_scale in the TCP control block are 0 (no scaling).
		 *
		 * Do window scaling?
		 */
		if ((tp->t_flags & (tcpcb::TF_RCVD_SCALE | tcpcb::TF_REQ_SCALE)) ==
			(tcpcb::TF_RCVD_SCALE | tcpcb::TF_REQ_SCALE))
		{
			tp->snd_scale = tp->requested_s_scale;
			tp->rcv_scale = tp->request_r_scale;
		}

		/*
		 *	Pass queued data to process
		 *	Any data queued for the connection can now be passed to the process. This is done
		 *	by tcp_reass with a null pointer as the second argument. This data would have
		 *	arrived with the SYN that moved the connection into the SYN_RCVD state.
		 */
		(void)tcp_reass(tp, nullptr, nullptr, tcpreass);

		/*
		 *	snd_wl1 is set to the received sequence number minus 1. We'll see in Figure 29.15
		 *	that this causes the three window update variables to be updated.
		 */
		tp->snd_wl1 = ti->ti_seq() - 1;

		/* fall into ...
		 *
		 *	Fast Retransmit and Fast Recovery Algorithms:
		 *	The next part of ACK processing, shown in Figure 29.3, handles duplicate ACKs and
		 *	determines if TCP's fast retransmit and fast recovery algorithms [Jacobson 1990c]
		 *	should come into play. The two algorithms are separate but are normally implemented
		 *	together [Floyd 1994).
		 *		a.	The fast retransmit algorithm occurs when TCP deduces from a small number
		 *			(normally 3) of consecutive duplicate ACKs that a segment has been lost and
		 *			deduces the starting sequence number of the missing segment. The missing segment
		 *			is retransmitted. The algorithm is mentioned in Section 4.2.2.21 of
		 *			RFC 1122, which states that TCP may generate an immediate ACK when an out-of-order
		 *			segment is received. We saw that Net/3 generates the immediate
		 *			duplicate ACKs in Figure 27.15. This algorithm first appeared in the 4.3BSD
		 *			Tahoe release and the subsequent Net/1 release. In these two implementations,
		 *			after the missing segment was retransmitted, the slow start phase was entered.
		 *		b.	The fast recovery algorithm says that after the fast retransmit algorithm (that is,
		 *			after the missing segment has been retransmitted), congestion avoidance but not
		 *			slow start is performed. This is an improvement that allows higher throughput
		 *			under moderate congestion, especially for large windows. This algorithm
		 *			appeared in the 4.3BSD Reno release and the subsequent Net/2 release.
		 *
		 *	Net/3 implements both fast retransmit and fast recovery, as we describe shortly.
		 *	In the discussion of Figure 24.17 we noted that an acceptable ACK must be in the range:
		 *			snd_una < acknowledgment field <= snd_max
		 *	This first test of the acknowledgment field compares it only to snd_una. The comparison
		 *	against snd_max is in Figure 29.5. The reason for separating the tests is so that the
		 *	following five tests can be applied to the received segment:
		 *		1.	If the acknowledgment field is less than or equal to snd_una, and
		 *		2.	the length of the received segment is 0, and
		 *		3.	the advertised window (tiwin) has not changed, and
		 *		4.	TCP has outstanding data that has not been acknowledged (the retransmission timer is nonzero), and
		 *		5.	the received segment contains the biggest ACK TCP has seen (the acknowledgment field equals snd_una),
		 *
		 *	then this segment is a completely duplicate ACK. (Tests l, 2, and 3 are in Figure 29.3;
		 *	tests 4 and 5 are at the beginning of Figure 29.4.)
		 *		TCP counts the number of these duplicate ACKs that are received in a row (in the
		 *	variable t_dupacks), and when the number reaches a threshold of 3
		 *	(tcprexmtthresh), the lost segment is retransmitted. This is the fast retransmit algorithm
		 *	described in Section 21.7 of Volume 1. It works in conjunction with the code we
		 *	saw in Figure 27.15: when TCP receives an out-of-order segment, it is required to generate
		 *	an immediate duplicate ACK, telling the other end that a segment might have been
		 *	lost and telling it the value of the next expected sequence number. The goal of the fast
		 *	retransmit algorithm is for TCP to retransmit immediately what appears to be the missing
		 *	segment, instead of waiting for the retransmission timer to expire. Figure 21.7 of
		 *	Volume 1 gives a detailed example of how this algorithm works.
		 *		The receipt of a duplicate ACK also tells TCP that a packet has "left the network,"
		 *	because the other end had to receive an out-of-order segment to send the duplicate
		 *	ACK. The fast recovery algorithm says that after some number of consecutive duplicate
		 *	ACKs have been received, TCP should perform congestion avoidance (i.e., slow down)
		 *	but need not wait for the pipe to empty between the two connection end points (slow
		 *	start). The expression "a packet has left the network" means a packet has been received
		 *	by the other end and has been added to the out-of-order queue for the connection. The
		 *	packet is not still in transit somewhere between the two end points.
		 *		If only the first three tests shown earlier are true, the ACK is still a duplicate and is
		 *	counted by the statistic tcps_rcvdupack, but the counter of the number of consecutive
		 *	duplicate ACKs for this connection (t_dupacks) is reset to O. If only the first test is
		 *	true, the counter t_dupacks is reset to O.
		 *		The remainder of the fast recovery algorithm is shown in Figure 29.4. When all five
		 *	tests are true, the fast recovery algorithm processes the segment depending on the number
		 *	of these consecutive duplicate ACKs that have been received.
		 *		1.	t_dupacks equals 3 (tcprexmtthresh). Congestion avoidance is performed
		 *			and the missing segment is retransmitted.
		 *		2.	t_dupacks exceeds 3. Increase the congestion window and perform normal TCP output.
		 *		3.	t_dupacks is less than 3. Do nothing.
		 *
		* In ESTABLISHED state: drop duplicate ACKs; ACK out of range
		* ACKs.  If the ack is in the range
		*	tp->snd_una < ti->ti_ack <= tp->snd_max
		* then advance tp->snd_una to ti->ti_ack and drop
		* data from the retransmission queue.  If this ACK reflects
		* more up to date window information we update our window information.
		*/
	case tcpcb::TCPS_ESTABLISHED:
	case tcpcb::TCPS_FIN_WAIT_1:
	case tcpcb::TCPS_FIN_WAIT_2:
	case tcpcb::TCPS_CLOSE_WAIT:
	case tcpcb::TCPS_CLOSING:
	case tcpcb::TCPS_LAST_ACK:
	case tcpcb::TCPS_TIME_WAIT:

		if (tcpcb::SEQ_LEQ(ti->ti_ack(), tp->snd_una)) {
			if (ti->ti_len() == 0 && tiwin == tp->snd_wnd) {

				/*
				* If we have outstanding data (other than
				* a window probe), this is a completely
				* duplicate ack (ie, window info didn't
				* change), the ack is the biggest we've
				* seen and we've seen exactly our rexmtthreshhold
				* of them, assume a packet
				* has been dropped and retransmit it.
				* Kludge snd_nxt & the congestion
				* window so we send only this one
				* packet.
				*
				* We know we're losing at the current
				* window size so do congestion avoidance
				* (set ssthresh to half the current window
				* and pull our congestion window back to
				* the new ssthresh).
				*
				* Dupacks mean that packets have left the
				* network (they're now cached at the receiver)
				* so bump cwnd by the amount in the receiver
				* to keep a constant cwnd packets in the
				* network.
				*/
				/*	if (tp->t_timer[TCPT_REXMT] == 0 ||	ti->ti_ack() != tp->snd_una)
						tp->t_dupacks = 0;*/

						/*
						 *	Number of consecutive duplicate ACKs reaches threshold of 3:
						 *	When t_dupacks reaches 3 (tcprexmtthresh), the value of snd_nxt is saved in
						 *	onxt and the slow start threshold (ssthresh) is set to one-half the current congestion
						 *	window, with a minimum value of two segments. This is what was done with the slow
						 *	start threshold when the retransmission timer expired in Figure 25.27, but we'll see later
						 *	in this piece of code that the fast recovery algorithm does not set the congestion window
						 *	to one segment, as was done with the timeout.
						 */
				if (++tp->t_dupacks == tcprexmtthresh) {
					tcp_dupacks_handler(tp, ti->ti_ack());
				}

			}

			/*
			 *	This statement is executed when the received segment contains a duplicate ACK,
			 *	but either the length is nonzero or the advertised window changed. Only the first of the
			 *	five tests described earlier is true. The counter of consecutive duplicate ACI<s is set to 0.
			 */
			else
				tp->t_dupacks = 0;

			/*
				*	Skip remainder of ACK processing:
				*	This break is executed in three cases:
				*		(1)	only the first of the five tests described earlier is true, or
				*		(2)	only the first three of the five tests is true, or
				*		(3)	the ACK is a duplicate, but the number of consecutive duplicates
				*			is less than the threshold of 3.
				*	For any of these cases the ACK is still a duplicate and the break goes to the end of the switch
				*	that started in Figure 29.2, which continues processing at the label step6.
				*	To understand the purpose in this aggressive window manipulation, consider the
				*	following example. Assume the window is eight segments, and segments 1 through 8
				*	are sent. Segment 1 is lost, but the remainder arrive OK and arc acknowledged. After
				*	the ACKs for segments 2, 3, and 4 arrive, the missing segment (1) is retransmitted. TCP
				*	would like the subsequent ACKs for 5 through 8 to allow some of the segments starting
				*	with 9 to be sent, to keep the pipe full. But the window is 8, which prevents segments 9
				*	and above from being sent. Therefore, the congestion window is temporarily inflated
				*	by one segment each time another duplicate ACK is received, since the receipt of the
				*	duplicate ACK tells TCP that another segment has left the pipe at the other end. When
				*	the acknowledgment of segment 1 is finally received, the next figure reduces the congestion
				*	window back to the slow start threshold. This increase in the congestion window
				*	as the duplicate ACKs arrive, and its subsequent decrease when the fresh ACK
				*	arrives, can be seen visually in Figure 21.10 of Volume 1.
				*/
			break;	/* beyond ACK processing (to step 6) */
		}

		/*
		 *	Check for out-of-range ACK:
		 *	Recall the definition of an acceptable ACK,
		 *		snd_una < acknowledgment field <= snd_max
		 *	If the acknowledgment field is greater than snd_max, the other end is acknowledging
		 *	data that TCP hasn't even sent yet! This probably occurs on a high-speed connection
		 *	when the sequence numbers wrap and a missing ACK reappears later. As we can see in
		 *	Figure 24.5, this rarely happens (since today's networks aren't fast enough).
		 */
		if (tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max))
			return dropafterack(tp, dropsocket, tiflags);

		/*
		 *	Calculate number of bytes acknowledged:
		 *	At this point TCP knows that it has an acceptable ACK. acked is the number of
		 *	bytes acknowledged.
		 */
		int acked(ti->ti_ack() - tp->snd_una);

		/*
		 *	The next part of ACK processing deals with RIT measurements and the retransmission timer.
		 *
		 *	Update RTT estimators:
		 *	If either:
		 *		(1)	a timestamp option was present, or
		 *		(2)	a segment was being timed and the
		 *			acknowledgment number is greater than the starting sequence number of the segment being timed,
		 *	tcp_xmit_timer updates the RTI estimators. Notice that the second
		 *	argument to this function when timestamps are used is the current time (tcp_now)
		 *	minus the timestamp echo reply (ts_ecr) plus 1 (since the function subtracts 1).
		 *	Delayed ACKs are the reason for the greater-than test of the sequence numbers. For
		 *	example, if TCP sends and times a segment with bytes 1-1024, followed by a segment
		 *	with bytes 1025-2048, if an ACK of 2049 is returned, this test will consider whether 2049
		 *	is greater than 1 (the starting sequence number of the segment being timed), and since
		 *	this is true, the RTT estimators are updated.
		 *
		* If we have a timestamp reply, update smoothed
		* round trip time. If no timestamp is present but
		* transmit timer is running and timed sequence
		* number was acked, update smoothed round trip time.
		* Since we now have an rtt measurement, cancel the
		* timer backoff (cf., Phil Karn's retransmit alg.).
		* Recompute the initial retransmit timer.
		*/
		if (ts_present)
			tp->tcp_xmit_timer(static_cast<short>(tcp_now - ts_ecr + 1));
		else if (tp->t_rtt && tcpcb::SEQ_GT(ti->ti_ack(), tp->t_rtseq))
			tp->tcp_xmit_timer(tp->t_rtt);

		/*
		 *	Check If all outstanding data has been acknowledged:
		 *	If the acknowledgment field of the received segment (ti_ack) equals the maximum
		 *	sequence number that TCP has sent (snd_max), all outstanding data has been
		 *	acknowledged. The retransmission timer is turned off and the needoutput flag is set
		 *	to 1. This flag forces a call to tcp_output at the end of this function. Since there is no
		 *	more data waiting to be acknowledged, TCP may have more data to send that it has not
		 *	been able to send earlier because the data was beyond the right edge of the window.
		 *	Now that a new ACK has been received, the window will probably move to the right
		 *	(snd_una is updated in Figure 29.8), which could allow more data to be sent.
		 *
		* If all outstanding data is acked, stop retransmit
		* timer and remember to restart (more output or persist).
		* If there is more data to be acked, restart retransmit
		* timer, using current (possibly backed-off) value.
		*/
		if (ti->ti_ack() == tp->snd_max) {
			tp->t_timer[TCPT_REXMT] = 0;
			needoutput = 1;
		}

		/*
		 *	Unacknowledged data outstanding:
		 *	Since there is additional data that has been sent but not acknowledged, if the persist
		 *	timer is not on, the retransmission timer is restarted using the current value of t_rxtcur.
		 */
		else if (tp->t_timer[TCPT_PERSIST] == 0)
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

		/*
		 *	Karn's Algorithm and Timestamps:
		 *	Notice that timestamps overrule the portion of Karn's algorithm (Section 21.3 of
		 *	Volume 1) that says: when a timeout and retransmission occurs, the RTT estimators cannot
		 *	be updated when the acknowledgment for the retransmitted data is received (the
		 *	retransmission ambiguity problem). In Figure 25.26 we saw that t_rtt was set to 0 when
		 *	a retransmission took place, because of Karn's algorithm. If timestamps are not present
		 *	and it is a retransmission, the code in Figure 29.6 does not update the RTT estimators
		 *	because t_rtt will be 0 from the retransmission. But if a timestamp is present, t_rtt
		 *	isn't examined, allowing the RTT estimators to be updated using the received timestamp
		 *	echo reply. With RFC 1323 timestamps the ambiguity is gone since the ts_ecr
		 *	value was copied by the other end from the segment being acknowledged. The other
		 *	half of Karn's algorithm, specifying that an exponential backoff must be used with
		 *	retransmissions, still holds, of course.
		 *
		 *	Update congestion window:
		 *	One of the rules of slow start and congestion avoidance is that a received ACK
		 *	increases the congestion window. By default the congestion window is increased by
		 *	one segment for each received ACK (slow start). But if the current congestion window
		 *	is greater than the slow start threshold, it is increased by 1 divided by the congestion
		 *	window, plus a constant fraction of a segment. The term
		 *		incr * incr / cw
		 *	is
		 *		t_maxseg * t_maxseg I snd_cwnd
		 *	which is 1 divided by the congestion window, taking into account that snd_cwnd is
		 *	maintained in bytes, not segments. The constant fraction is the segment size divided by
		 *	8. The congestion window is then limited by the maximum value of the send window
		 *	for this connection. Example calculations of this algorithm are in Section 21.8 of Volume 1.
		 *		Remark:	Adding in the constant fraction (the segment size divided by 8) is wrong [Floyd 1994]. But it
		 *				has been in the BSD sources since 4.3BSD Reno and is still in 4.4BSD and Net/3. It should be removed.
		 *
		* When new data is acked, open the congestion window.
		* If the window gives us less than ssthresh packets
		* in flight, open exponentially (maxseg per packet).
		* Otherwise open linearly: maxseg per window
		* (maxseg * (maxseg / cwnd) per packet).
		*/
		tcp_congestion_conrol_handler(tp);


		/*
		 *	The next part of tcp_input removes the acknowledged data from the send buffer.
		 *
		 *	Remove acknowledged bytes from the send buffer:
		 *	If the number of bytes acknowledged exceeds the number of bytes on the send buffer,
		 *	snd_wnd is decremented by the number of bytes in the send buffer and TCP knows
		 *	that its FIN has been ACKcd. That nu1nber of bytes is then removed from the send
		 *	buffer by sbdrop. This method for detecting the ACK of a FIN works only because the
		 *	FIN occupies 1 byte in the sequence number space.
		 */
		int ourfinisacked;
		//so->so_snd.sb_mutex.lock();
		auto dropped = so->so_snd.sbdrops(acked);
		tp->snd_wnd -= dropped;
		ourfinisacked = acked > dropped;
		//if (static_cast<u_long>(acked) > so->so_snd.size()) {
		//	tp->snd_wnd -= so->so_snd.size();
		//	so->so_snd.sbdrop(static_cast<int>(so->so_snd.size()));
		//	ourfinisacked = 1;
		//}
		//
		///*	
		// *	Otherwise the number of bytes acknowledged is less than or equal to the number of
		// *	bytes in the send buffer, so ourfinisacked is set to 0, and acked bytes of data are
		// *	dropped from the send buffer.
		// */
		//else {
		//	//so->so_snd.sbdrops(acked);
		//	tp->snd_wnd -= acked;
		//	ourfinisacked = 0;
		//}
		//so->so_snd.sb_mutex.unlock();
		/*
		 *	Wakeup processes waiting on send buffer:
		 *	sowwakeup awakens any processes waiting on the send buffer. snd_una is
		 *	updated to contain the oldest unacknowledged sequence number. If this new value of
		 *	snd_una exceeds snd_nxt, the latter is updated, since the intervening bytes have been
		 *	acknowledged.
		 *	Figure 29.9 shows how snd_nxt can end up with a sequence number that is less
		 *	than snd_una. assume two segments are transmitted, the first with bytes 1-512 and
		 *	the second with bytes 513-1024.
		 *	1 2 ...	512				513 514 ... 1024 1025
		 *	-------------------->	-------------------->
		 *	/\	one segment				one segment		/\
		 *	||											||
		 *	snd_una										snd_nxt
		 *												snd_max
		 *	Figure 29.9 Two segments sent on a connection.
		 *
		 *	The retransmission timer then expires before an acknowledgment is returned. The code
		 *	in Figure 25.26 sets snd_nxt back to snd_una, slow start is entered, tcp_output is
		 *	called, and one segment containing bytes 1-512 is retransmitted. tcp_output
		 *	increases snd_nxt to 513, and we have the scenario shown in Figure 29.10.
		 *	1 2 ...	512					513 514 ... 1024 1025
		 *	-------------------->
		 *	/\	segment retransmitted	/\					/\
		 *	||							||					||
		 *	snd_una						snd_nxt				snd_max
		 *
		 *	Figure 29.10 Continuation of Figure 29.9 after retransmission timer expires.
		 *
		 *	At this point an ACK of 1025 arrives (either the two original segments or the ACK was
		 *	delayed somewhere in the network). The ACK is valid since it is less than or equal to
		 *	snd_max, but snd_nxt will be less than the updated value of snd_una.
		 */
		if (so->so_snd.sb_flags & socket::sockbuf::SB_NOTIFY)
			so->sowwakeup();

		if (tcpcb::SEQ_LT(tp->snd_nxt, (tp->snd_una = ti->ti_ack())))
			tp->snd_nxt = tp->snd_una;

		/*
		 *	The general ACK processing is now complete, and the switch handles four special cases.
		 */
		switch (tp->t_state) {

			/*
			 *	Receipt of ACK In FIN_WAIT_1 state:
			 *	In this state the process has closed the connection and TCP has sent the FIN. But
			 *	other ACKs can be received for data segments sent before the FIN. Therefore the connection
			 *	moves into the FIN_WAIT_2 state only when the FIN has been acknowledged.
			 *	The flag ourfinisacked is set in Figure 29.8; this depends on whether the number of
			 *	bytes ACKed exceeds the amount of data in the send buffer or not.
			 *
			* In FIN_WAIT_1 STATE in addition to the processing
			* for the ESTABLISHED state if our FIN is now acknowledged
			* then enter FIN_WAIT_2.
			*/
		case tcpcb::TCPS_FIN_WAIT_1:
			if (ourfinisacked) {

				/*
				 *	Set FIN_WAIT_2 timer:
				 *	We also described in Section 25.6 how Net/3 sets a FIN_WAIT_2 timer to prevent
				 *	an infinite wait in the FIN_WAIT_2 state. This timer is set only if the process completely
				 *	closed the connection (i.e., the close system call or its kernel equivalent if the
				 *	process was terminated by a signal), and not if the process performed a half-close (i.e.,
				 *	the FIN was sent but the process can still receive data on the connection).
				 *
				* If we can't receive any more
				* data, then closing user can proceed.
				* Starting the timer is contrary to the
				* specification, but if we don't get a FIN
				* we'll hang forever.
				*/
				if (so->so_state & socket::SS_CANTRCVMORE) {
					so->soisdisconnected();
					tp->t_timer[TCPT_2MSL] = tcp_maxidle;
				}
				tp->t_state = tcpcb::TCPS_FIN_WAIT_2;
			}
			break;

			/*
			 *	Receipt of ACK in CLOSING state:
			 *	If the ACK is for the FIN (and not for some previous data segment), the connection
			 *	moves into the TIME_WAIT state. Any pending timers are cleared (such as a pending
			 *	retransmission timer), and the TIME_WAIT timer is started with a value of twice the MSL.
			 *
			* In CLOSING STATE in addition to the processing for
			* the ESTABLISHED state if the ACK acknowledges our FIN
			* then enter the TIME-WAIT state, otherwise ignore
			* the segment.
			*/
		case tcpcb::TCPS_CLOSING:
			if (ourfinisacked) {
				tp->t_state = tcpcb::TCPS_TIME_WAIT;
				tp->tcp_canceltimers();
				tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
				so->soisdisconnected();
			}
			break;

			/*
			 *	Receipt of ACK In LAST_ACK state:
			 *	If the FIN is ACKed, the new state is CLOSED. This state transition is handled by
			 *	tcp_close, which also releases the Internet PCB and TCP control block.
			 *
			* In LAST_ACK, we may still be waiting for data to drain
			* and/or to be acked, as well as for the ack of our FIN.
			* If our FIN is now acknowledged, delete the TCB,
			* enter the closed state and return.
			*/
		case tcpcb::TCPS_LAST_ACK:
			if (ourfinisacked) {
				(void)tcp_close(*tp);
				return drop(tp, dropsocket);
			}
			break;

			/*
			 *	Receipt of ACK In TIME_WAIT state:
			 *	In this state both ends have sent a FIN and both FINs have been acknowledged. If
			 *	TCP's ACK of the remote FIN was lost, however, the other end will retransmit the FIN
			 *	(with an ACK). TCP drops the segment and resends the ACK. Additionally, the
			 *	TIME_WAIT timer must be restarted with a value of twice the MSL.
			 *
			* In TIME_WAIT state the only thing that should arrive
			* is a retransmission of the remote FIN.  Acknowledge
			* it and restart the finack timer.
			*/
		case tcpcb::TCPS_TIME_WAIT:
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			return dropafterack(tp, dropsocket, tiflags);
		}
	}

	return step6(tp, tiflags, ti, m, it, tiwin, needoutput);
}