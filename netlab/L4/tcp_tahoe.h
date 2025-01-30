#pragma once

#include "L4_TCP_impl.h"

/*
   tcp_tahoe
   A TCP Tahoe implementation - implementing congetion avoidance and fast retransmit.
*/
class tcp_tahoe : public L4_TCP_impl
{
 public:

	// Constructor
	tcp_tahoe(class inet_os& inet);

	// Destructor
	~tcp_tahoe() = default;

protected:

	/*
		tcp_dupacks_handler - Handles duplicate acknowledgments in TCP Tahoe.

		This function implements loss recovery in TCP Tahoe. Unlike TCP Reno, Tahoe does not
		perform fast recovery. Instead, upon detecting packet loss (via 3 duplicate ACKs), it
		immediately reduces the congestion window to one segment and re-enters slow start.

		* tp - Pointer to the TCP control block.
		* seq - Sequence number of the missing segment indicated by the duplicate ACK.
	*/
    void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) override;

	/*
		tcp_congestion_control_handler - Handles TCP congestion control for Tahoe.

		This function manages the congestion window (snd_cwnd) during the two phases of TCP Tahoe's congestion control:

		1. Slow Start: Exponential growth to quickly utilize available bandwidth.
		2. Congestion Avoidance: Linear growth after reaching the slow start threshold (snd_ssthresh).

		* tp - Pointer to the TCP control block.
	*/
    void tcp_congestion_conrol_handler(tcpcb* tp) override;

	/*
		tcp_rto_timer_handler - Handles retransmission timeout (RTO) events in TCP Tahoe.

		This function is invoked when the retransmission timer expires, indicating that
		the acknowledgment for a sent packet has not been received within the expected time.
		It calculates a new retransmission timeout value, reduces the congestion window to
		prevent network overload, and prepares for retransmission using slow start.

		* tp - Pointer to the TCP control block.
	*/
    void tcp_rto_timer_handler(tcpcb* tp) override;
};