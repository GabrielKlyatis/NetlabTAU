#pragma once

/*
	NETLAB_L4_TCP_DEBUG
	Define in order to printout the L4_TCP packets for debug.
*/
//#define NETLAB_L4_TCP_DEBUG

/*
	NETLAB_NO_REASS_MBUF
	Define in order to disable the REASS_MBUF macro.
*/
#define NETLAB_NO_REASS_MBUF
//#undef NETLAB_NO_REASS_MBUF

/*
	NETLAB_NO_TCP_RESPOND
	Define in order to disable tcp_respond (to avoid sending resets) for debug.
*/
#define NETLAB_NO_TCP_RESPOND
#undef NETLAB_NO_TCP_RESPOND


#include <iostream>
#include <fstream>


#include "../L3/L3.h"
#include "../infra/pcb.h"
#include "L4_UDP_Impl.hpp"

// User-settable options (used with setsockopt).
#ifdef TCP_NODELAY
#undef TCP_NODELAY
#endif
#define	TCP_NODELAY	0x01	/* Don't delay send to coalesce packets */

#ifdef TCP_MAXSEG
#undef TCP_MAXSEG
#endif
#define	TCP_MAXSEG	0x02	/* Set maximum segment size */

/***************************************************************************************/
/*								L4_TCP - Headers & Control Block					   */
/***************************************************************************************/

struct tcphdr
{
	/*
		Defines an alias representing the two 4-bit pack of offset and x2, according to windows
		byte order (BIG_ENDIAN).
	*/
	typedef u_char_pack th_off_x2_pack;

	// For BSD consistency.
	typedef	u_long		tcp_seq;

	// Flags for TCP header.
	enum TH_
	{
		TH_FIN = 0x01,  /*!< The FIN flag */
		TH_SYN = 0x02,  /*!< The SYN flag */
		TH_RST = 0x04,  /*!< The RST flag */
		TH_PUSH = 0x08, /*!< The PUSH flag */
		TH_ACK = 0x10,  /*!< The ACK flag */
		TH_URG = 0x20,  /*!< The URG flag */
		TH_ECE = 0x40,  /*!< The th ECE flag */
		TH_CWR = 0x80,  /*!< The th CWR flag */
		TH_FLAGS = (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG | TH_ECE | TH_CWR) /*!< all flags */
	};

	tcphdr()
		: th_sport(0), th_dport(0), th_seq(0), th_ack(0), th_off_x2(th_off_x2_pack(0, 0)), th_flags(0), th_win(0), th_sum(0), th_urp(0) { }

	// Stream insertion operator.
	friend std::ostream& operator<<(std::ostream& out, const struct tcphdr& tcp);

	// Gets the data offset.
	inline	const u_char th_off() const { return th_off_x2.hb; }

	// Gets the unused.
	inline	const u_char th_x2() const { return th_off_x2.lb; }

	// Sets the data offset.
	inline	void th_off(const u_char& th_off) { th_off_x2.hb = th_off; }

	// Sets the unused.
	inline	void th_x2(const u_char& ip_hl) { th_off_x2.lb = ip_hl; }

	u_short	th_sport;		/* Source port */
	u_short	th_dport;		/* Destination port */
	tcp_seq	th_seq;			/* Sequence number */
	tcp_seq	th_ack;			/* Acknowledgment number */

	th_off_x2_pack th_off_x2;   /* Data offset then unused */

	u_char	th_flags;   /* The flags \see TH_ */
	u_short	th_win;		/* Window */
	u_short	th_sum;		/* Checksum */
	u_short	th_urp;		/* Urgent pointer */
};

struct tcpiphdr
{
	// For BSD consistency.
	typedef	u_long		tcp_seq;

	// Overlay for ip header used by other protocols (TCP, UDP).
	struct ipovly
	{
		// Default constructor.
		ipovly();

		/*
			Constructor
				* ih_pr - The ip header protocol.
				* ih_len - The ip header parameter ip_len (total length).
				* ih_src - The IP source address.
				* ih_dst - The IP destination address.
		*/
		ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst);

		// Stream insertion operator.
		friend std::ostream& operator<<(std::ostream& out, const struct tcpiphdr::ipovly& ip);

		struct tcpiphdr* ih_next, * ih_prev;			/* For protocol sequence q's */
		u_char	ih_x1 = 0x00;		/* (unused) */
		u_char	ih_pr;				/* Protocol */
		short	ih_len;				/* Protocol length */
		struct	in_addr ih_src;		/* Source internet address */
		struct	in_addr ih_dst;		/* Destination internet address */
	};

	// Default constructor.
	tcpiphdr();

	/*
		Constructor from received packet, does the casting.
			* m - If non-null, the byte to process.
			* ih_pr - The ip header protocol.
			* ip_len - The ip header parameter ip_len (total length).
			* ip_src - The IP source address.
			* ip_dst - The IP destination address.
	*/
	tcpiphdr(byte* m, const u_char& ih_pr, const short& ip_len, const in_addr& ip_src, const in_addr& ip_dst);

	// Stream insertion operator.
	friend std::ostream& operator<<(std::ostream& out, const struct tcpiphdr& ti);

	inline	struct tcpiphdr* ti_next() { return ti_i.ih_next; }
	inline	void ti_next(struct tcpiphdr* ih_next) { ti_i.ih_next = ih_next; }

	inline	struct tcpiphdr* ti_prev() { return ti_i.ih_prev; }

	inline	void ti_prev(struct tcpiphdr* ih_prev) { ti_i.ih_prev = ih_prev; }

	inline	u_char& ti_x1() { return ti_i.ih_x1; }
	inline	const u_char& ti_x1() const { return ti_i.ih_x1; }

	inline	u_char& ti_pr() { return ti_i.ih_pr; }
	inline	const u_char& ti_pr() const { return ti_i.ih_pr; }

	inline	short& ti_len() { return ti_i.ih_len; }
	inline	const short& ti_len() const { return ti_i.ih_len; }

	inline	struct	in_addr& ti_src() { return ti_i.ih_src; }
	inline	const struct	in_addr& ti_src() const { return ti_i.ih_src; }

	inline	struct	in_addr& ti_dst() { return ti_i.ih_dst; }
	inline	const struct	in_addr& ti_dst() const { return ti_i.ih_dst; }

	inline	u_short& ti_sport() { return ti_t.th_sport; }
	inline	const u_short& ti_sport() const { return ti_t.th_sport; }

	inline	u_short& ti_dport() { return ti_t.th_dport; }
	inline	const u_short& ti_dport() const { return ti_t.th_dport; }

	inline	tcp_seq& ti_seq() { return ti_t.th_seq; }
	inline	const tcp_seq& ti_seq() const { return ti_t.th_seq; }

	inline	tcp_seq& ti_ack() { return ti_t.th_ack; }
	inline	const tcp_seq& ti_ack() const { return ti_t.th_ack; }

	inline	void ti_x2(const u_char& th_x2) { ti_t.th_x2(th_x2); }
	inline	const u_char ti_x2() { return ti_t.th_x2(); }

	inline	void ti_off(const u_char& th_off) { ti_t.th_off(th_off); }
	inline	const u_char ti_off() { return ti_t.th_off(); }

	inline	u_char& ti_flags() { return ti_t.th_flags; }
	inline	const u_char& ti_flags() const { return ti_t.th_flags; }

	inline	u_short& ti_win() { return ti_t.th_win; }
	inline	const u_short& ti_win() const { return ti_t.th_win; }

	inline	u_short& ti_sum() { return ti_t.th_sum; }
	inline	const u_short& ti_sum() const { return ti_t.th_sum; }

	inline	u_short& ti_urp() { return ti_t.th_urp; }
	inline	const u_short& ti_urp() const { return ti_t.th_urp; }

	/*
		tcp_template Function -
		Create template to be used to send tcp packets on a connection. Call after host entry
		created, allocates an mbuf and fills in a skeletal tcp/ip header, minimizing the amount
		of work necessary when the connection is used.

			* inp_faddr - The foreign host table entry.
			* inp_fport - The foreign port.
			* inp_laddr - The local host table entry.
			* inp_lport - The local port.
	*/
	void tcp_template(const struct in_addr& inp_faddr, const u_short& inp_fport, const struct in_addr& inp_laddr, const u_short& inp_lport);

	inline std::shared_ptr<std::vector<byte>> REASS_MBUF();

	/*!
		insque Function - Insert the given head to the global PCB linked list.
			* head - The head of the linked list.
	*/
	inline void insque(struct tcpiphdr& head);

	// Remove this object from the linked list (does not delete it).
	inline void remque();

	struct	ipovly ti_i;	/* Overlaid ip structure */
	struct	tcphdr ti_t;	/* TCP header */
};

class tcpcb : public inpcb_impl
{
	friend class L4_TCP;
	friend class L4_TCP_impl;
	friend class tcp_tahoe;
	friend class tcp_reno;

public:

	// TCP FSM state definitions - Per RFC793, September, 1981.
	enum TCPS_
	{
		TCPS_CLOSED = 0,		/* Closed */
		TCPS_LISTEN = 1,		/* Listening for connection */
		TCPS_SYN_SENT = 2,		/* Active, have sent syn */
		TCPS_SYN_RECEIVED = 3,	/* Have send and received syn */

		/* states < TCPS_ESTABLISHED are those where connections not established */
		TCPS_ESTABLISHED = 4,	/* Established */
		TCPS_CLOSE_WAIT = 5,	/* RCVD FIN, waiting for close */

		/* states > TCPS_CLOSE_WAIT are those where user has closed */
		TCPS_FIN_WAIT_1 = 6,	/* Have closed, sent FIN */
		TCPS_CLOSING = 7,		/* Closed xchd FIN; await FIN ACK */
		TCPS_LAST_ACK = 8,		/* Had FIN and close; await FIN ACK */

		/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
		TCPS_FIN_WAIT_2 = 9,	/* Have closed, fin is acked */
		TCPS_TIME_WAIT = 10,	/* In 2 * msl quiet wait after close */
		TCP_NSTATES = 11		/* The TCP number of states */
	};

	// Flags for tcpcb
	enum TF_
	{
		TF_ACKNOW = 0x0001,		/* ACK peer immediately */
		TF_DELACK = 0x0002,		/* ACK, but try to delay it */
		TF_NODELAY = 0x0004,	/* Don't delay packets to coalesce */
		TF_NOOPT = 0x0008,		/* Don't use tcp options */
		TF_SENTFIN = 0x0010,	/* Have sent FIN */
		TF_REQ_SCALE = 0x0020,	/* Have/will request window scaling */
		TF_RCVD_SCALE = 0x0040,	/* Other side has requested scaling */
		TF_REQ_TSTMP = 0x0080,	/* Have/will request timestamps */
		TF_RCVD_TSTMP = 0x0100,	/* A timestamp was received in SYN */
		TF_SACK_PERMIT = 0x0200	/* Other side said I could SACK */
	};

	// Flags for TCP out-of-band.
	enum TCPOOB_
	{
		TCPOOB_HAVEDATA = 0x01,
		TCPOOB_HADDATA = 0x02
	};

	enum
	{
		TCPT_NTIMERS = 4	/* The tcpt number of timers */
	};

	// Constructor
	tcpcb(inet_os& inet)
		: inpcb_impl(inet), seg_next(nullptr), seg_prev(nullptr), t_state(0),
		t_rxtshift(0), t_rxtcur(0), t_dupacks(0), t_maxseg(0), t_force(0),
		t_flags(0), t_template(nullptr), t_inpcb(dynamic_cast<inpcb_impl*>(this)),
		snd_una(0), snd_nxt(0), snd_up(0), snd_wl1(0), snd_wl2(0), iss(0), snd_wnd(0),
		rcv_wnd(0), rcv_nxt(0), rcv_up(0), irs(0), rcv_adv(0), snd_max(0),
		snd_ssthresh(0), t_idle(0), t_rtt(0), t_rtseq(0), t_srtt(0), t_rttvar(0),
		t_rttmin(0), max_sndwnd(0), t_oobflags(0), t_iobc(0), t_softerror(0),
		snd_scale(0), rcv_scale(0), request_r_scale(0), requested_s_scale(0),
		ts_recent(0), ts_recent_age(0), last_ack_sent(0), t_tuba_pcb(nullptr),
		log(tcpcb_logger()) { }

	/*
		Create a new TCP control block, making an empty reassembly queue and hooking it to the
		argument protocol control block.
			* so - The so.
			* head - The head.
	*/
	tcpcb(socket& so, inpcb_impl& head)
		: inpcb_impl(so, head), seg_next(nullptr), seg_prev(nullptr), t_state(0),
		t_rxtshift(0), t_rxtcur(0), t_dupacks(0), t_maxseg(0), t_force(0),
		t_flags(0), t_template(nullptr), t_inpcb(dynamic_cast<inpcb_impl*>(this)),
		snd_una(0), snd_nxt(0), snd_up(0), snd_wl1(0), snd_wl2(0), iss(0), snd_wnd(0),
		rcv_wnd(0), rcv_nxt(0), rcv_up(0), irs(0), rcv_adv(0), snd_max(0),
		snd_ssthresh(0), t_idle(0), t_rtt(0), t_rtseq(0), t_srtt(0), t_rttvar(0),
		t_rttmin(0), max_sndwnd(0), t_oobflags(0), t_iobc(0), t_softerror(0),
		snd_scale(0), rcv_scale(0), request_r_scale(0), requested_s_scale(0),
		ts_recent(0), ts_recent_age(0), last_ack_sent(0), t_tuba_pcb(nullptr),
		log(tcpcb_logger()) { }

	// Destructor. Free the reassembly queue, if any, and gets rid of all other allocated stuff.
	tcpcb::~tcpcb()
	{
		/* Free the reassembly queue, if any */
		struct tcpiphdr* t(seg_next);
		while (t != reinterpret_cast<struct tcpiphdr*>(this))
			delete reinterpret_cast<struct tcpiphdr*>(t->ti_next());
		if (t_template)
			delete t_template;
		if (this != dynamic_cast<class tcpcb*>(t_inpcb))
			delete t_inpcb;
		inp_ppcb = nullptr;
		dynamic_cast<socket*>(inp_socket)->soisdisconnected();
	}

	// Determines if we have received SYN.
	inline bool TCPS_HAVERCVDSYN() const;

	// Determines if we have received FIN.
	inline bool TCPS_HAVERCVDFIN() const;

	/*
		tcp_outflags Function -
		Flags used when sending segments in tcp_output. Basic flags (TH_RST,TH_ACK,TH_SYN,TH_FIN)
		are totally determined by state, with the proviso that TH_FIN is sent only if all data
		queued for output is included in the segment.
	*/
	inline const u_char tcp_outflags() const;

	/*
		intotcpcb Function - A tcpcb* caster from inpcb_impl.
			* ip - If non-null, the inpcb_impl to cast.
	*/
	static inline class tcpcb* intotcpcb(class inpcb_impl* ip);
	static inline class tcpcb* intotcpcb(class inpcb* ip);

	/*
		sototcpcb Function - A tcpcb* caster from socket.
			* so - If non-null, the socket to cast.
	*/
	static inline class tcpcb* sototcpcb(socket* so);

	/*
		SEQ_LT Function - Sequence less than.
			* T - Generic type parameter.
			* a - The T to process.
			* b - The T to process.
	*/
	template<typename T>
	static inline bool SEQ_LT(T a, T b);

	/*
		SEQ_LEQ Function - Sequence less than or equal.
			* T - Generic type parameter.
			* a - The T to process.
			* b - The T to process.
	*/
	template<typename T>
	static inline bool SEQ_LEQ(T a, T b);

	/*
		SEQ_GT Function - Sequence greater than.
			* T - Generic type parameter.
			* a - The T to process.
			* b - The T to process.
	*/
	template<typename T>
	static inline bool SEQ_GT(T a, T b);

	/*
		SEQ_GEQ Function - Sequence greater than or equal.
			* T - Generic type parameter.
			* a - The T to process.
			* b - The T to process.
	*/
	template<typename T>
	static inline bool SEQ_GEQ(T a, T b);

	/*
		in_pcblookup Function - Calls inpcb_impl::in_pcblookup().
			* faddr - The foreign host table entry.
			* fport_arg - The foreign port.
			* laddr - The local host table entry.
			* lport_arg - The local port.
			* flags - The flags.
	*/
	virtual class tcpcb* in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags);

	/*
		tcp_template Function -
		Create template to be used to send tcp packets on a connection. Call after host entry
		created, allocates an mbuf and fills in a skeletal tcp/ip header, minimizing the amount
		of work necessary when the connection is used.
	*/
	void tcp_template();


	// Macros to initialize tcp sequence number for receive from initial receive sequence number.
	inline void tcp_rcvseqinit();

	// Macros to initialize tcp sequence number for send from initial send sequence number.
	inline void tcp_sendseqinit();

	/*
		When a source quench is received, close congestion window to one segment.  We will
		gradually open it again as we proceed.
	*/
	inline void tcp_quench();

	/*
		TCP_REXMTVAL Function -
		The initial retransmission should happen at rtt + 4 * rttvar.
	*/
	inline short TCP_REXMTVAL() const;

	/*
		tcp_xmit_timer Function -
		Collect new round-trip time estimate and update averages and current timeout.
			* rtt - The rtt.
	*/
	void tcp_xmit_timer(short rtt);

	/*
		tcp_canceltimers() Function -
		Cancel all timers for TCP tp. The function tcp_canceltimers is called by tcp_input
		when the TIME_ WAIT state is entered. All four timer counters are set to 0, which
		turns off the retransmission, persist, keepalive, and FIN_WAIT_2 timers,
		before tcp_input sets the 2MSL timer.
	*/
	void tcp_canceltimers();

	void log_snd_cwnd(u_long snd_cwnd);


	struct	tcpiphdr* seg_next;	/* Sequencing queue next */
	struct	tcpiphdr* seg_prev;	/* Sequencing queue prev */

	short	t_state;			/* State of this connection */

	short	t_timer[TCPT_NTIMERS];	/* TCP timers */
	short	t_rxtshift;	/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;	/* Current retransmit value */
	short	t_dupacks;	/* Consecutive dup acks recd */

	u_short	t_maxseg;	/* Maximum segment size */
	char	t_force;	/* 1 if forcing out a byte */

	u_short	t_flags;	/* Flags */

	struct	tcpiphdr* t_template;	/* Skeletal packet for transmit */

	class	inpcb_impl* t_inpcb;	/* Back pointer to internet pcb */

	/*
		The following fields are used as in the protocol specification.
		See RFC783, Dec. 1981, page 21.
	*/

	/* Send sequence variables */
	tcp_seq	snd_una;		/* Send unacknowledged */
	tcp_seq	snd_nxt;		/* Send next */
	tcp_seq	snd_up;			/* Send urgent pointer */
	tcp_seq	snd_wl1;		/* Window update seg seq number */
	tcp_seq	snd_wl2;		/* Window update seg ack number */
	tcp_seq	iss;			/* Initial send sequence number */
	u_long	snd_wnd;		/* Send window */

	/* receive sequence variables */
	u_long	rcv_wnd;		/* Receive window */
	tcp_seq	rcv_nxt;		/* Receive next */
	tcp_seq	rcv_up;			/* Receive urgent pointer */
	tcp_seq	irs;			/* Initial receive sequence number */

	/* Additional variables for this implementation. */

	/* Receive variables */
	tcp_seq	rcv_adv;		/* Advertised window */

	/* Retransmit variables */
	tcp_seq	snd_max;		/* Highest sequence number sent; used to recognize retransmits */

	/* Congestion control (for slow start, source quench, retransmit after loss) */
	u_long	snd_cwnd;		/* congestion-controlled window */
	u_long	snd_ssthresh;	/* snd_cwnd size threshold for for slow start exponential to linear switch */

	/*
		Transmit timing - See below for scale of srtt and rttvar.
		"Variance" is actually smoothed difference.
	*/
	u_short	t_idle;			/* Inactivity time */
	short	t_rtt;			/* Round trip time */
	tcp_seq	t_rtseq;		/* Sequence number being timed */
	short	t_srtt;			/* Smoothed round-trip time */
	short	t_rttvar;		/* Variance in round-trip time */
	u_short	t_rttmin;		/* Minimum rtt allowed */
	u_long	max_sndwnd;		/* Largest window peer has offered */

	/* Out-of-band data */
	char	t_oobflags;		/* Have some */
	char	t_iobc;			/* Input character */
	short	t_softerror;	/* Possible error not yet reported */

	/* RFC 1323 variables */
	u_char	snd_scale;			/* Window scaling for send window */
	u_char	rcv_scale;			/* Window scaling for recv window */
	u_char	request_r_scale;	/* Pending window scaling reciever */
	u_char	requested_s_scale;  /* Pending window scaling send */
	u_long	ts_recent;			/* Timestamp echo data */
	u_long	ts_recent_age;		/* When last updated */
	tcp_seq	last_ack_sent;		/* The last acknowledge sent */

	/* TUBA */
	char* t_tuba_pcb;		/* Next level down pcb for TCP over z */

	class tcpcb_logger {

		friend class tcpcb;
	public:
		~tcpcb_logger() { log.close(); }
		typedef std::chrono::duration<double> seconds;
		tcpcb_logger();
		tcpcb_logger(const tcpcb_logger&)
		{
			//tcpcb_logger(); // UNCOMMENT FOR TCP LOGS
		}

		void update(u_long snd_cwnd);

		std::ofstream log;
		std::chrono::time_point<std::chrono::high_resolution_clock> start;
		static int log_number;
	};

	tcpcb_logger log;
};

/***************************************************************************************/
/*							L4_TCP - Interface & Implementation						   */
/***************************************************************************************/

class L4_TCP : public protosw 
{
public:

	// Defines an alias representing netlab::sockets.
	typedef	class netlab::L5_socket_impl socket;

	// For BSD consistency.
	typedef	u_long		tcp_seq;

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

	enum TCP_things
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

	// Constructor 
	L4_TCP(class inet_os &inet) 
		: protosw(inet, SOCK_STREAM, NULL, IPPROTO_TCP, PR_CONNREQUIRED | PR_WANTRCVD), tcb(inet) { }

	// Destructor
	~L4_TCP()
	{
		if (tcp_saveti)
			delete tcp_saveti;
		if (tcp_last_inpcb)
			delete tcp_last_inpcb;
	}

	// TCP initialization.
	virtual void pr_init() = 0;

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
	virtual void pr_input(const struct pr_input_args &args) = 0;

	// Wrapper for tcp_output.
	virtual int pr_output(const struct pr_output_args &args) = 0;

	/*
		tcp_output Function - The actual function, with the desired arguments. This function handles the transmission of TCP segments.

		 It constructs TCP headers, segments data to fit the Maximum Segment Size (MSS), applies flow control (using cwnd and rwnd),
		 and manages retransmissions for reliability. It computes checksums, attaches options (like SACK or timestamps),
		 updates sequence numbers, and passes packets to the IP layer for transmission.
		 The function ensures compliance with TCP's flow control, congestion control,
		 and retransmission mechanisms to maintain reliable data delivery.

			* tp - The TCP control block of this connection.
	*/
	virtual int tcp_output(tcpcb& tp) = 0;

	/*
		pr_usrreq Function - TCP's user-request function is called for a variety of operations. 
			* so - If non-null, the socket that request something.
			* req - The request to perform.
			* m - The std::shared_ptr<std::vector<byte>> to process, generally the input data.
			* nam - If non-null, the nam additional parameter, usually sockaddr.
			* nam_len - Length of the nam.
			* control - The control (unused).
	*/
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>> &m,
		struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;

	// pr_fasttim Function - Fast timeout routine for processing delayed acks.
	virtual void pr_fasttimo() = 0;

	// pr_slowtimo Function - Slow timeout routine for processing delayed acks.
	virtual void pr_slowtimo() = 0;

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
	virtual void pr_drain() { }
	virtual int pr_sysctl() { return 0; }
	virtual void pr_ctlinput() { }
	virtual int pr_ctloutput() { return 0; }


	// Handlers
	virtual void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) {}
	virtual void tcp_congestion_conrol_handler(tcpcb* tp);
	virtual void tcp_rto_timer_handler(tcpcb* tp);

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
	static inline void tcp_pulloutofband(socket& so, const tcpiphdr& ti, std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

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

	// TCP control block, one per TCP.
	class tcpcb tcb;	/* The tcb head of the linked list of all connections */
	class inpcb_impl* tcp_last_inpcb;	/* The last seen inpcb, a small cache that show good results. */
	int	tcp_maxidle;	/* The TCP max idle */
	u_long	tcp_now;	/* For RFC 1323 timestamps */
	tcp_seq	tcp_iss;	/* TCP initial send seq # Increment for tcp_iss each second. This is designed to increment at the standard 250 KB/s, but with a random component averaging 128 KB. We also increment tcp_iss by a quarter of this amount each time we use the value for a new connection. If defined, the tcp_random18() macro should produce a number in the range [0-0x3ffff] that is hard to predict. */

	u_long	tcp_sendspace;   /* The TCP send space */
	u_long	tcp_recvspace;   /* The TCP recv space */

	const int 	tcp_mssdflt = TCP_MSS;  /* Patchable/settable default MSS for tcp */
	const int 	tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;   /* Patchable/settable parameters for tcp round trip time */
	const int	tcp_do_rfc1323 = 0;		/* The patchable/settable do rfc1323 for tcp */

	const int	tcp_keepidle = TCPTV_KEEP_IDLE;			/* The TCP keep idle */
	const int	tcp_keepintvl = TCPTV_KEEPINTVL;		/* The TCP keep intvl */
	const int	tcp_keepcnt = TCPTV_KEEPCNT;			/* Max idle probes */
	const int	tcp_maxpersistidle = TCPTV_KEEP_IDLE;	/* Max idle time in persist */
	const int	tcprexmtthresh = 3; /* The tcp retransmit threshold */
	const struct tcpiphdr* tcp_saveti = nullptr;
};