#include "tcp_tahoe.h"


void tcp_tahoe::tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq)
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
	if (tp->t_dupacks > tcprexmtthresh)
	{
		tp->log_snd_cwnd(tp->snd_cwnd += tp->t_maxseg);
		(void)tcp_output(*tp);
		return drop(tp, dropsocket);
	}

	u_int win(std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg);
	if (win < 2)
		win = 2;

	tp->snd_ssthresh = win * tp->t_maxseg;

	/*
	 *	Turn off retransmission timer:
	 *	The retransmission timer is turned off and, in case a segment is currently being
	 *	timed, t_rtt is set to 0.
	 */
	tp->t_timer[TCPT_REXMT] = 0;
	tp->t_rtt = 0;

	/*
	 *	Retransmit missing segment:
	 *	snd_nxt is set to the starting sequence number of the segment that appears to have
	 *	been lost (the acknowledgment field of the duplicate ACK) and the congestion window
	 *	is set to one segment. This causes tcp_output to send only the missing segment.
	 *	(This is shown by segment 63 in Figure 21.7 of Volume 1.)
	 */
	tcp_seq onxt(tp->snd_nxt);
	tp->snd_nxt = seq;
	tp->log_snd_cwnd(tp->snd_cwnd = tp->t_maxseg);
	(void)tcp_output(*tp);

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

	return drop(tp, dropsocket);
}

void tcp_tahoe::tcp_congestion_conrol_handler(tcpcb* tp)
{
	u_int cw(tp->snd_cwnd);
	float incr(tp->t_maxseg);

	if (cw > tp->snd_ssthresh)
		// congetion control
		incr *= incr / cw
		// + incr / 8		/*	REMOVED	*/
		;

	// slow start increase
	tp->log_snd_cwnd(tp->snd_cwnd = std::min(cw + (u_int)std::floor(incr), static_cast<u_int>(TCP_MAXWIN << tp->snd_scale)));

}

void tcp_tahoe::tcp_rto_timer_handler(tcpcb* tp)
{
	TCPT_RANGESET(tp->t_rxtcur, static_cast<int>(tp->TCP_REXMTVAL() * tcp_backoff(tp->t_rxtshift)),
		tp->t_rttmin, static_cast<int>(TCPTV_REXMTMAX));
	tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

	/*
		* Close the congestion window down to one segment
		* (we'll open it by one segment for each ack we get).
		* Since we probably have a window's worth of unacked
		* data accumulated, this "slow start" keeps us from
		* dumping all that data as back-to-back packets (which
		* might overwhelm an intermediate gateway).
		*
		* There are two phases to the opening: Initially we
		* open by one mss on each ack.  This makes the window
		* size increase exponentially with time.  If the
		* window is larger than the path can handle, this
		* exponential growth results in dropped packet(s)
		* almost immediately.  To get more time between
		* drops but still "push" the network to take advantage
		* of improving conditions, we switch from exponential
		* to linear window opening at some threshhold size.
		* For a threshhold, we use half the current window
		* size, truncated to a multiple of the mss.
		*
		* (the minimum cwnd that will give us exponential
		* growth is 2 mss.  We don't allow the threshhold
		* to go below this.)
		*/

	u_int win(std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg);
	if (win < 2)
		win = 2;
	tp->log_snd_cwnd(tp->snd_cwnd = tp->t_maxseg);
	tp->snd_ssthresh = win * tp->t_maxseg;
	tp->t_dupacks = 0;

}