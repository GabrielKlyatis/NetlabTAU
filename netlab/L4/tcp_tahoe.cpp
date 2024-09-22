

#include "tcp_tahoe.h"

tcp_tahoe::tcp_tahoe(inet_os& inet) : L4_TCP_impl(inet) {}

void tcp_tahoe::tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq)
{
	int dropsocket = 0;

	// After 3 duplicate ACKs, we enter loss recovery in Tahoe (no fast recovery like Reno).
	if (tp->t_dupacks == tcprexmtthresh)
	{
		// Reduce ssthresh to half of the current window size.
		u_int win = std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
		if (win < 2)
			win = 2;
		tp->snd_ssthresh = win * tp->t_maxseg;

		// Set congestion window to one segment (slow start behavior after detecting loss).
		tp->log_snd_cwnd(tp->snd_cwnd = tp->t_maxseg);

		// Retransmit the missing segment.
		tcp_seq onxt(tp->snd_nxt);
		tp->snd_nxt = seq;
		(void)tcp_output(*tp);

		// Restore snd_nxt to continue from where we left off.
		if (L4_TCP::tcpcb::SEQ_GT(onxt, tp->snd_nxt))
			tp->snd_nxt = onxt;

		// Clear RTT measurements.
		tp->t_timer[TCPT_REXMT] = 0;
		tp->t_rtt = 0;

		return drop(tp, dropsocket);
	}
}

void tcp_tahoe::tcp_congestion_conrol_handler(tcpcb* tp)
{
	u_int cw(tp->snd_cwnd);
	float incr(tp->t_maxseg);

	// congetion control
	if (cw > tp->snd_ssthresh)
		// Tahoe: simple linear increase in congestion avoidance
		incr = incr / cw;

	// Slow start: exponential growth
	tp->snd_cwnd  = std::min(cw + (u_int)std::floor(incr), static_cast<u_int>(TCP_MAXWIN << tp->snd_scale));

	tp->log_snd_cwnd(tp->snd_cwnd);
}

void tcp_tahoe::tcp_rto_timer_handler(tcpcb* tp)
{
	// calculates and sets a new retransmission timeout (RTO) 
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