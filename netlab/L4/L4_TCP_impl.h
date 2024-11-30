#pragma once

#include "L4_TCP.h"

/***************************************************************************************/
/*							L4_TCP_impl - Student Implementation					   */
/***************************************************************************************/

class L4_TCP_impl : public L4_TCP {
public:

	/*
	Constructor - IMPLEMENTED FOR YOU
		* inet - The inet.
*/
	L4_TCP_impl(class inet_os& inet) : L4_TCP(inet) { }

	/*
		Destructor - IMPLEMENTED FOR YOU
		Deletes the tcp_saveti, and the tcp_last_inpcb if space has been allocated for them.
	*/
	~L4_TCP_impl()
	{
		if (tcp_saveti)
			delete tcp_saveti;
		if (tcp_last_inpcb)
			delete tcp_last_inpcb;
	}

	// Wrapper for tcp_output.
	virtual int pr_output(const struct pr_output_args& args);

	/*
		tcp_output Function - The actual function, with the desired arguments. This function handles the transmission of TCP segments.

		 It constructs TCP headers, segments data to fit the Maximum Segment Size (MSS), applies flow control (using cwnd and rwnd), 
		 and manages retransmissions for reliability. It computes checksums, attaches options (like SACK or timestamps), 
		 updates sequence numbers, and passes packets to the IP layer for transmission. 
		 The function ensures compliance with TCP's flow control, congestion control, 
		 and retransmission mechanisms to maintain reliable data delivery.

			* tp - The TCP control block of this connection.
	*/
	virtual int tcp_output(tcpcb& tp);

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
	virtual void pr_input(const struct pr_input_args& args);

	/* Ignore the following function declarations */
	virtual void pr_init();
	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control);
	virtual void pr_fasttimo();
	virtual void pr_slowtimo();
	virtual void trimthenstep6(class tcpcb* tp, int& tiflags, tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long& tiwin, int& needoutput);
	virtual void tcp_dooptions(class tcpcb& tp, u_char* cp, int cnt, tcpiphdr& ti, int& ts_present, u_long& ts_val, u_long& ts_ecr);
	virtual void tcp_respond(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const tcp_seq& ack, const tcp_seq& seq, const int& flags);
	virtual void dropafterack(class tcpcb* tp, const int& dropsocket, const int& tiflags);
	virtual void dropwithreset(class inpcb_impl* inp, const int& dropsocket, const int& tiflags, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, tcpiphdr* ti);
	virtual void drop(class inpcb_impl* inp, const int dropsocket);
	virtual int again(tcpcb& tp, const bool idle, socket& so);
};