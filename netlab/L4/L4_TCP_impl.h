#pragma once

#include "L4_TCP.h"

/***************************************************************************************/
/*									 L4_TCP_impl									   */
/***************************************************************************************/

class L4_TCP_impl : public L4_TCP {
public:

/***************************************************************************************/
/***************************************************************************************/
/*				STUDENT IMPLEMENTATION SECTION BELOW - IGNORE THE REST				   */
/***************************************************************************************/
/***************************************************************************************/

	// Wrapper for tcp_output.
	virtual int pr_output(const struct pr_output_args& args) override;

	/*
		tcp_output Function - The actual function, with the desired arguments. This function handles the transmission of TCP segments.

		 It constructs TCP headers, segments data to fit the Maximum Segment Size (MSS), applies flow control (using cwnd and rwnd), 
		 and manages retransmissions for reliability. It computes checksums, attaches options (like SACK or timestamps), 
		 updates sequence numbers, and passes packets to the IP layer for transmission. 
		 The function ensures compliance with TCP's flow control, congestion control, 
		 and retransmission mechanisms to maintain reliable data delivery.

			* tp - The TCP control block of this connection.
	*/
	virtual int tcp_output(tcpcb& tp) override;

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
	virtual void pr_input(const struct pr_input_args& args) override;

/***************************************************************************************/
/***************************************************************************************/
/*				STUDENT IMPLEMENTATION SECTION ABOVE - IGNORE THE REST				   */
/***************************************************************************************/
/***************************************************************************************/


	


public:

	/*
		Constructor
			* inet - The inet.
	*/
	L4_TCP_impl(class inet_os& inet);

	// Destructor - Deletes the tcp_saveti, and the tcp_last_inpcb if space has been allocated for them.
	~L4_TCP_impl();

//	virtual void pr_init();
//	virtual void pr_fasttimo();
//	virtual void pr_slowtimo();
//

	
};