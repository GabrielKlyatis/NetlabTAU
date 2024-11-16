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
	inline int tcp_output(tcpcb& tp);

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

/***************************************************************************************/
/***************************************************************************************/
/*				STUDENT IMPLEMENTATION SECTION ABOVE - IGNORE THE REST				   */
/***************************************************************************************/
/***************************************************************************************/





	// Defines an alias representing netlab::sockets.
	typedef	class netlab::L5_socket_impl socket;
	
	// For BSD consistency.
	typedef	u_long		tcp_seq;

protected:
	// Handlers
	virtual void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) {}
	virtual void tcp_congestion_conrol_handler(tcpcb* tp);
	virtual void tcp_rto_timer_handler(tcpcb* tp);

public:

	enum TCPT_
	{
		TCPT_REXMT = 0,		/* Retransmit */
		TCPT_PERSIST = 1,	/* Retransmit persistence */
		TCPT_KEEP = 2,		/* Keep alive */
		TCPT_2MSL = 3,		/* 2 * msl quiet time timer */
		TCPT_NTIMERS = 4
	};

	// Time constants.
	enum TCPTV_
	{
		TCPTV_MSL = 30 * PR_SLOWHZ,				/* Max seg lifetime (hah!) */
		TCPTV_SRTTBASE = 0,						/* Base roundtrip time; if 0, no idea yet */
		TCPTV_SRTTDFLT = 3 * PR_SLOWHZ,			/* Assumed RTT if no info */
		TCPTV_PERSMIN = 5 * PR_SLOWHZ,			/* Retransmit persistence */
		TCPTV_PERSMAX = 60 * PR_SLOWHZ,			/* Maximum persist interval */
		TCPTV_KEEP_INIT = 75 * PR_SLOWHZ,		/* Initial connect keep alive */
		TCPTV_KEEP_IDLE = 120 * 60 * PR_SLOWHZ,	/* Default time before probing */
		TCPTV_KEEPINTVL = 75 * PR_SLOWHZ,		/* Default probe interval */
		TCPTV_KEEPCNT = 8,						/* Max probes before drop */
		TCPTV_MIN = 1 * PR_SLOWHZ,				/* Minimum allowable value */
		TCPTV_REXMTMAX = 64 * PR_SLOWHZ			/* Max allowable REXMT value */
	};

	enum TCP_
	{
		TCP_RTT_SCALE = 8,		/* Multiplier for srtt; 3 bits frac. */
		TCP_RTT_SHIFT = 3,		/* Shift for srtt; 3 bits frac. */
		TCP_RTTVAR_SCALE = 4,	/* Multiplier for rttvar; 2 bits */
		TCP_RTTVAR_SHIFT = 2	/* Multiplier for rttvar; 2 bits */
	};

	enum TCP_things // rename
	{
		MAX_TCPOPTLEN = 32,		/* Max # bytes that go in options */
		TCP_MSS = 512,			/* Default maximum segment size for TCP. With an IP MSS of 576, this is 536, but 512 is probably more convenient. This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)). */
		TCP_LINGERTIME = 120,	/* Linger at most 2 minutes */
		TCP_MAXRXTSHIFT = 12,	/* Maximum retransmits */
		TCP_MAX_WINSHIFT = 14,	/* Maximum window shift */
		TCP_MAXWIN = 65535,		/* Largest value for (unscaled) window */
		TCP_PAWS_IDLE = (24 * 24 * 60 * 60 * PR_SLOWHZ), /* The TCP paws idle option */
		tcp_totbackoff = 511	/* Sum of tcp_backoff[] */
	};

	/*
		Constructor
			* inet - The inet.
	*/
	L4_TCP_impl(class inet_os& inet);

	// Destructor - Deletes the tcp_saveti, and the tcp_last_inpcb if space has been allocated for them.
	~L4_TCP_impl();

	virtual void pr_init();
	virtual void pr_fasttimo();
	virtual void pr_slowtimo();

	/*
		TCPT_RANGESET Function - Force a time value to be in a certain range.
			* tv - The TV.
			* value - The value.
			* tvmin - The tvmin.
			* tvmax - The tvmax.
	*/
	template<typename T, typename V, typename MIN, typename MAX>
	static inline void TCPT_RANGESET(T& tv, const V value, const MIN tvmin, const MAX tvmax)
	{
		if ((tv = value) < tvmin)
			tv = tvmin;
		else if (tv > tvmax)
			tv = tvmax;
	}

protected:

	// Flags for tcp options.
	enum TCPO_
	{
		TCPOPT_EOL = 0, /* The tcpopt EOL option */
		TCPOPT_NOP = 1, /* The tcpopt nop option */
		TCPOPT_MAXSEG = 2,  /* The maxseg option */
		TCPOLEN_MAXSEG = 4, /* The maxseg option length */
		TCPOPT_WINDOW = 3,  /* The window option */
		TCPOLEN_WINDOW = 3, /* The window option length */
		TCPOPT_SACK_PERMITTED = 4,	/* Experimental */
		TCPOLEN_SACK_PERMITTED = 2, /* The sack permitted option length */
		TCPOPT_SACK = 5,			/* Experimental */
		TCPOPT_TIMESTAMP = 8,   /* The timestamp option */
		TCPOLEN_TIMESTAMP = 10, /* The timestamp option length */
		TCPOLEN_TSTAMP_APPA = (TCPOLEN_TIMESTAMP + 2), /* Appendix A */
		TCPOPT_TSTAMP_HDR = (TCPOPT_NOP << 24 | TCPOPT_NOP << 16 | TCPOPT_TIMESTAMP << 8 | TCPOLEN_TIMESTAMP), /* The timestamp option header */
	};

	/* 
		TSTMP_LT Function - For modulo comparisons of timestamps.
			* T - Generic type parameter.
			* U - Generic type parameter.
			* a - The T to process.
			* b - The U to process.
	*/
	template<typename T, typename U = T>
	static inline bool TSTMP_LT(T a, U b) { return static_cast<int>(a - b) < 0; }

	/*
		TSTMP_GEQ Function - For modulo comparisons of timestamps.
			* T - Generic type parameter.
			* U - Generic type parameter.
			* a - The T to process.
			* b - The U to process.
	*/
	template<typename T, typename U = T>
	static inline bool TSTMP_GEQ(T a, U b) { return static_cast<int>(a - b) >= 0; }

public:

	// Process User Requests.
	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control);
protected:

	/*
		tcp_attach Function - Attach TCP protocol to socket, allocating internet protocol control block, tcp control block, buffer space, 
		and entering LISTEN state if to accept connections.
			* so - The so.
	*/
	inline int tcp_attach(socket& so);

	/*
		tcp_newtcpcb Function - A new TCP control block is allocated and initialized by tcp_newtcpcb().
			* so - The so.
	*/
	inline class tcpcb* tcp_newtcpcb(socket& so);

	/*
		tcptimers Function - TCP timer processing.
			* tp - If non-null, the TP.
			* timer - The timer.
	*/
	inline class tcpcb* tcp_timers(class tcpcb* tp, int timer);

	/*
		tcp_setpersist Function - The function uses TCP's retransmission timeout calculations. This function called when the persist timer expired. This timer is set when TCP has data to send on a connection, but the other end is advertising a window of 0. This function, calculates and stores the next value for the timer.
			* tp - The TP.
	*/
	static inline void tcp_setpersist(class tcpcb& tp);

	/*
		tcp_backoff Function - When window is full, exponentially backoff for retransmit.
			* backoff - The backoff power.
	*/
	static int tcp_backoff(const int backoff);

	/*
		tcp_disconnect Function - Initiate (or continue) disconnect.
			* tp - The TP.
	*/
	inline class tcpcb* tcp_disconnect(class tcpcb& tp);

	/*
		tcp_usrclosed Function - User issued close, and wishs to trail through shutdown states.
			* tp - The TP.
	*/
	inline void tcp_usrclosed(class tcpcb& tp);

	/*
		tcp_drop Function -  Drop a TCP connection, reporting the specified error. If connection is synchronized, then send a RST to peer.
			* tp - The TP.
			* err - The error.
	*/
	inline void tcp_drop(class tcpcb& tp, const int err);

	/*
	
		tcp_close Function - Close a TCP control block: discard all space held by the tcp, discard internet protocol block, wake up any sleepers.
			* tp - The TP.
	*/
	inline class tcpcb* tcp_close(class tcpcb& tp);
	
	// Arguments used by tcp_output.
	struct tcp_output_args : public pr_output_args
	{
		/*!
			Constructor
				* tp - The TP.
		*/
		tcp_output_args(tcpcb& tp);

		tcpcb& tp;  /* The tcpcb to pass */
	};

	/* 
		again Function - Send more than one segment.
			* tp - The tcpcb of this connection.
			* idle - The idle bool for timers.
			* so - The socket that requested the send.
	*/ 
	inline int again(tcpcb& tp, const bool idle, socket& so);

	/*
		send Function - The last half of tcp_output sends the segment-it fills in all the fields in the TCP header and 
		passes the segment to IP for output. The first part sends the MSS and window scale options with a SYN segment.

			* tp - The tcpcb of this connection.
			* idle - The idle bool for timers (in case we recall again).
			* so - The socket that requested the send.
			* sendalot - The sendalot (decides if we are to call again() again.
			* off - The off (should we rais the #TH_PUSH flag?).
			* flags - The flags of the send packet.
			* win - The window size.
			* len - The length of the packet.
	*/
	inline int send(tcpcb& tp, const bool idle, socket& so, bool sendalot, int& off, int& flags, long& win, long& len);

	/*
		out Function - Handles ENOBUFS, EHOSTUNREACH and ENETDOWN errors, throws the others.
			* tp - The tcpcb of this connection.
			* error - The error.
	*/
	static inline int out(tcpcb& tp, int error);

	/*
		drop Function - 
		Drop (without ACK or RST): tcp_trace is called when a segment is dropped without
		generating an ACK or an RST. If the SO_DEBUG flag is set and an ACK is generated,
		tcp_output generates a trace record. If the SO_DEBUG flag is set and an RST is generated,
		a trace record is not generated for the RST.

			* inp - The inp holding the socket to abort.
			* dropsocket - The dropsocket.
	
	*/
	inline void drop(class inpcb_impl* inp, const int dropsocket);

	/*
		dropafterack Function - 
		An ACK is generated only if the RST flag was not set. (A segment with an RST is never
		ACKed.) The mbuf chain containing the received segment is released, and tcp_output
		generates an immediate ACK.
			* tp - The tcpcb holding the socket to abort.
			* dropsocket - The drop socket?.
			* tiflags - The tcpiphdr flags.

	*/
	inline void dropafterack(class tcpcb* tp, const int& dropsocket, const int& tiflags);

	/*
		dropwithreset Function - 
		A RST is generated unless the received segment also contained an RST, or the received
		segment was sent as a broadcast or multicast. An RST is never generated in response to an
		RST, since this could lead to RST storms (a continual exchange of RST segments between
		two end points).
			* inp - inp	inp	If non-null, the tcpcb holding the socket to abort.
			* dropsocket - Drop socket?.
			* tiflags - The tcpiphdr flags.
			* m - The std::shared_ptr<std::vector<byte>> to strip.
			* it - The iterator, as the current offset in the vector.
			* ti - If non-null, the tcpiphdr.
	*/
	inline void dropwithreset(class inpcb_impl* inp, const int& dropsocket, const int& tiflags, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, tcpiphdr* ti);

	/*
		Note - The funny name is for consistency with the freeBSD link name. 
	
		step6 Function - Update Window Information.
			* tp - The tcpcb holding the socket to abort.
			* tiflags - The tcpiphdr flags.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector
	*/
	inline void step6(class tcpcb* tp, int& tiflags, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long& tiwin, int& needoutput);

	/*
		tcp_pulloutofband Function - Pull out of band byte out of a segment so it doesn't appear in the user's data queue.
			* so - If non-null, the soocket.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector<byte>> to strip.
			* it - The iterator, as the current offset in the vector.
	*/
	static inline void tcp_pulloutofband(socket& so, const L4_TCP::tcpiphdr& ti, std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

	/*
		dodata Function - Processing of Received Data: tcp_input continues by taking the received data (if any) and
		either appending it to the socket's receive buffer (if it is the next expected segment)
		or placing it onto the socket's out-of-order queue.

			* tp - If non-null, the tcpcb holding the socket to abort.
			* tiflags - The tcpiphdr flags.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector<byte>> to strip.
			* it - The iterator, as the current offset in the vector.
			* needoutput - The need output?.
	*/
	inline void dodata(class tcpcb* tp, int& tiflags, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const int& needoutput);

	/*
		TCP_REASS Function - Insert segment ti into reassembly queue of tcp with control block tp. 
		Return TH_FIN if reassembly now includes a segment with FIN. The macro form does the common case inline 
		(segment is the next to be received on an established connection, and the queue is empty), 
		avoiding linkage into and removal from the queue and repetition of various conversions. Set DELACK for segments received in order, 
		but ack immediately when segments are out of order (so fast retransmit can work).
			* tp - If non-null, the tcpcb holding the socket to abort.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator, as the current offset in the vector.
			* so - If non-null, the socket.
			* flags - The flags.
	*/
	inline void TCP_REASS(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, socket* so, int& flags);

	/*
		tcp_reass Function - Reassemble a segment off of the reassembly queue of tcp with control block tp. 
		Return TH_FIN if the reassembly now includes a segment with FIN. The macro form does the common case inline 
		(segment is the next to be received on an established connection, and the queue is empty), 
		avoiding linkage into and removal from the queue and repetition of various conversions. 
		Set DELACK for segments received in order, but ack immediately when segments are out of order (so fast retransmit can work).
			* tp - If non-null, the tcpcb holding the socket to abort.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator, as the current offset in the vector.
	*/
	inline int tcp_reass(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it);

	/*
		present Function - Present data to user, advancing rcv_nxt through completed sequence space.
			* tp - a pointer to the TCP control block for the received segment.
			* ti - a pointer to the IP and TCP headers of the received segment.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator.
	*/
	inline int present(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it);

	/*
		tcp_respond Function - 
		Send a single message to the TCP at address specified by the given TCP/IP header.
		If m == nullptr, then we make a copy of the tcpiphdr at ti and send directly to the addressed
		host.

			* tp - a pointer to the TCP control block for the received segment.
			* ti - a pointer to the IP and TCP headers of the received segment.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator.
			* ack - The acknowledge number.
			* seq - The sequence number.
			* flags - The TCP flags.
	*/
	inline void tcp_respond(class tcpcb* tp, struct tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const tcp_seq& ack, const tcp_seq& seq, const int& flags);

	/*
		tcp_dooptions Function - 
		This function processes the five TCP options supported by Net/3 (Section 26.4): the EOL,
		NOP, MSS, window scale, and timestamp options. Figure 28.9 shows the first part of this
		function.

			* tp - a pointer to the TCP control block for the received segment.
			* cp - If non-null, the cp to hold the options.
			* cnt - the size of cp.
			* ti - a pointer to the IP and TCP headers of the received segment.
			* ts_present - timestamp present?
			* ts_val - The timestamp value.
			* ts_ecr - The timestamp ecr.
	*/
	inline void tcp_dooptions(class tcpcb& tp, u_char* cp, int cnt, tcpiphdr& ti, int& ts_present, u_long& ts_val, u_long& ts_ecr);

	/*
		tcp_mss Function - 
		Checks for a cached route to the destination and calculates the MSS
		to use for this connection. The first part of tcp_mss, which a route to the destination
		if one is not already held by the PCB.

		The tcp_mss() function is called from two other functions:
			1.	from tcp_output, when a SYN segment is being sent, to include an MSS option, and
			2. 	from tcp_input, when an MSS option is received in a SYN segment.

			* tp - a pointer to the TCP control block for the received segment.
			* offer - The mss offer.
	*/
	int tcp_mss(class tcpcb& tp, u_int offer);

	/*
		roundup Function - Roundups.
			* T - Generic type parameter.
			* U - Generic type parameter.
			* x - The T to process.
			* y - The U to process.
	*/
	template<typename T, typename U = T>
	static inline T roundup(T x, U y) { return ((x + (y - 1)) / y) * y; }

	/*
		trimthenstep6 Function - Handles any data received with the SYN.
			* tp - inp	If non-null, the tcpcb holding the socket to abort.
			* tiflags - The tcpiphdr flags.
			* ti - If non-null, the tcpiphdr.
			* m - The std::shared_ptr<std::vector<byte>> to strip.
			* it - The iterator, as the current offset in the vector.
			* tiwin - The tcpiphdr window.
			* needoutput - Need output?.
	*/
	inline void trimthenstep6(class tcpcb* tp, int& tiflags, tcpiphdr* ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long& tiwin, int& needoutput);

	/*
		TCP_ISSINCR Function - Increment for tcp_iss each second.
			* div - The div that divides the increment.
	*/
	inline void	TCP_ISSINCR(const int div = 4);

	/*
		print Function - Prints the tcpiphdr with #checksum as its th_sum, making sure to use the lock_guard.
		
			* tcpip - The tcpiphdr. (TCP IP header)
			* tcp_checksum - The checksum.
			* intro - The intro to print.
			* str - The output stream.
	*/
	inline void print(struct tcpiphdr& tcpip, uint16_t tcp_checksum, std::string intro = "[#] TCPIP pseudo header!", std::ostream& str = std::cout) const;

	// Same but with a TCP header.
	inline void print(struct tcphdr& tcp, uint16_t tcp_checksum, std::string intro = "[#] TCP packet received!", std::ostream& str = std::cout) const;

	class L4_TCP::tcpcb tcb;	/* The tcb head of the linked list of all connections */
	class inpcb_impl* tcp_last_inpcb;	/* The last seen inpcb, a small cache that show good results. */
	int	tcp_maxidle;	/* The TCP max idle */
	u_long	tcp_now;	/* For RFC 1323 timestamps */
	tcp_seq	tcp_iss;	/* TCP initial send seq # Increment for tcp_iss each second. This is designed to increment at the standard 250 KB/s, but with a random component averaging 128 KB. We also increment tcp_iss by a quarter of this amount each time we use the value for a new connection. If defined, the tcp_random18() macro should produce a number in the range [0-0x3ffff] that is hard to predict. */

	u_long	tcp_sendspace;   /* The TCP send space */
	u_long	tcp_recvspace;   /* The TCP recv space */

	const int 	tcp_mssdflt = TCP_MSS;  /* Patchable/settable default MSS for tcp */
	const int 	tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;   /* Patchable/settable parameters for tcp round trip time */
	const int	tcp_do_rfc1323 = 1;		/* The patchable/settable do rfc1323 for tcp */

	const int	tcp_keepidle = TCPTV_KEEP_IDLE;			/* The TCP keep idle */
	const int	tcp_keepintvl = TCPTV_KEEPINTVL;		/* The TCP keep intvl */
	const int	tcp_keepcnt = TCPTV_KEEPCNT;			/* Max idle probes */
	const int	tcp_maxpersistidle = TCPTV_KEEP_IDLE;	/* Max idle time in persist */
	const int	tcprexmtthresh = 3; /* The tcp retransmit threshold */
	const struct tcpiphdr* tcp_saveti = nullptr;
};