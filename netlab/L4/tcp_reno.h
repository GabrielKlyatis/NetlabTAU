#pragma once

#include "tcp_tahoe.h"

/*
   tcp_reno
   A TCP Reno implementation - enhancing TCP Tahoe by adding fast recovery
   to improve performance during congestion events.
*/
class tcp_reno : public tcp_tahoe
{
public:

	// Constructor
	tcp_reno(class inet_os& inet);

	// Destructor
	~tcp_reno() = default;

protected:

	/*
		tcp_dupacks_handler - Handles duplicate acknowledgments in TCP Reno.

		This function implements the fast retransmit and fast recovery mechanisms
		in TCP Reno, reacting to duplicate ACKs to improve performance and
		respond to packet loss. It adjusts the congestion window (snd_cwnd)
		and retransmits missing segments as needed based on the number of
		duplicate ACKs received.

		* tp - Pointer to the TCP control block.
		* seq - Sequence number of the missing segment indicated by the duplicate ACK.
	*/
	void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) override;

	/*
		tcp_congestion_control_handler - Handles TCP congestion control for Reno.

		This function adjusts the congestion window (snd_cwnd) based on the current
		phase of TCP congestion control: slow start or congestion avoidance.

		* tp - Pointer to the TCP control block.
	*/
	void tcp_congestion_conrol_handler(tcpcb* tp) override;
};