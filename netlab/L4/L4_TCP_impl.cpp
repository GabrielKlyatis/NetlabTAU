#include "L4_TCP_impl.h"

/***************************************************************************************/
/*							L4_TCP_impl - Student Implementation					   */
/***************************************************************************************/

// // Wrapper for tcp_output.
int L4_TCP_impl::pr_output(const struct pr_output_args& args)
{
	// INSERT IMPLEMENTATION HERE
	return 0;
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
	// INSERT IMPLEMENTATION HERE
	return 0;
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
	// INSERT IMPLEMENTATION HERE
	return;
}