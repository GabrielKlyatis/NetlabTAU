#include "tcp_reno.h"


tcp_reno::tcp_reno(inet_os& inet) : tcp_tahoe(inet) {}

void tcp_reno::tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq)
{
	int dropsocket = 0;

	/*
	*	Number of consecutive duplicate ACKs exceeds threshold of 3:
	*	The missing segment was retransmitted when t_dupacks equaled 3, so the receipt
	*	of each additional duplicate ACK means that another packet has left the network. The
	*	congestion window is incremented by one segment. tcp_output sends the next segment
	*	in sequence, and the duplicate ACK is dropped. (This is shown by segments 67,
	*	69, and 71 in Figure 21.7 of Volume 1.)
	*/
	// Fast Recovery: Increment congestion window for each duplicate ACK beyond 3
	if (tp->t_dupacks > tcprexmtthresh)
	{
		tp->log_snd_cwnd(tp->snd_cwnd += tp->t_maxseg);
		(void)tcp_output(*tp); // Send new segments
		return drop(tp, dropsocket);
	}

	// Enter fast retransmit and recovery on 3 duplicate ACKs
	if (tp->t_dupacks == tcprexmtthresh)
	{

		u_int win(std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg);
		if (win < 2)
			win = 2;

		tp->snd_ssthresh = win * tp->t_maxseg;


		/*
		 *	Retransmit missing segment:
		 *	snd_nxt is set to the starting sequence number of the segment that appears to have
		 *	been lost (the acknowledgment field of the duplicate ACK) and the congestion window
		 *	is set to one segment. This causes tcp_output to send only the missing segment.
		 *	(This is shown by segment 63 in Figure 21.7 of Volume 1.)
		 */
		tcp_seq onxt(tp->snd_nxt);
		tp->snd_nxt = seq;
		tp->snd_cwnd = tp->t_maxseg;
		(void)tcp_output(*tp);

		/*
		 *	Set congestion window:
		 *	The congestion window is set to the slow start threshold plus the number of segments
		 *	that the other end has cached. By cached we mean the number of out-of-order
		 *	segments that the other end has received and generated duplicate ACKs for. These cannot
		 *	be passed to the process at the other end until the missing segment (which was just
		 *	sent) is received. Figures 21.10 and 21.11 in Volume 1 show what happens with the congestion
		 *	window and slow start threshold when the fast recovery algorithm is in effect.
		 */
		tp->snd_cwnd = tp->snd_ssthresh + tp->t_maxseg * tp->t_dupacks;

		/*
		 *	Set snd_nxt:
		 *	The value of the next sequence number to send is set to the maximum of its previous
		 *	value (onxt) and its current value. Its current value was modified by tcp_output
		 *	when the segment was retransmitted. Normally this causes snd_nxt to be set back to
		 *	its previous value, which means that only the missing segment is retransmitted, and
		 *	that future calls to tcp_output carry on with the next segment in sequence.
		 */
		if (L4_TCP::tcpcb::SEQ_GT(onxt, tp->snd_nxt))
			tp->snd_nxt = onxt;


		/*
		 *	Turn off retransmission timer:
		 *	The retransmission timer is turned off and, in case a segment is currently being
		 *	timed, t_rtt is set to 0.
		 */
		tp->t_timer[TCPT_REXMT] = 0;
		tp->t_rtt = 0;

	}

	/*
	*	Adjust congestion window:
	*	If the number of consecutive duplicate ACKs exceeds the threshold of 3, this is the
	*	first nonduplicate ACK after a string of four or more duplicate ACKs. The fast recovery
	*	algorithm is complete. Since the congestion window was incremented by one segment
	*	for every consecutive duplicate after the third, if it now exceeds the slow start threshold,
	*	it is set back to the slow start threshold. The counter of consecutive duplicate ACKs is
	*	set to 0.
	*
	* If the congestion window was inflated to account
	* for the other side's cached packets, retract it.
	*/
	if (tp->t_dupacks > tcprexmtthresh && tp->snd_cwnd > tp->snd_ssthresh)
	{
		tp->snd_cwnd = tp->snd_ssthresh;
		tp->t_dupacks = 0;
	}

	// update log once
	tp->log_snd_cwnd(tp->snd_cwnd);

	return drop(tp, dropsocket);
}

void tcp_reno::tcp_congestion_conrol_handler(tcpcb* tp)
{
	u_int cw(tp->snd_cwnd);
	float incr(tp->t_maxseg);

	// congetion control
	if (cw > tp->snd_ssthresh)
		// Reno: smoother additive increase in congestion avoidance 
		incr *= incr / cw;

	// Slow start: exponential growth
	tp->snd_cwnd = std::min(cw + (u_int)std::floor(incr), static_cast<u_int>(TCP_MAXWIN << tp->snd_scale));

	tp->log_snd_cwnd(tp->snd_cwnd);
}


