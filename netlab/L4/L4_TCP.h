#pragma once

/*!
	\def	NETLAB_L4_TCP_DEBUG
	Define in order to printout the L4_TCP packets for debug.
*/
//#define NETLAB_L4_TCP_DEBUG

/*!
	\def	NETLAB_NO_REASS_MBUF
	Define in order to disable the REASS_MBUF macro.
*/
#define NETLAB_NO_REASS_MBUF
//#undef NETLAB_NO_REASS_MBUF
/*!
	\def	NETLAB_NO_TCP_RESPOND
	Define in order to disable tcp_respond (to avoid sending resets) for debug.
*/
#define NETLAB_NO_TCP_RESPOND
#undef NETLAB_NO_TCP_RESPOND

#include "../L3/L3.h"
#include "../infra/pcb.h"
#include "L4_UDP_Impl.hpp"

/*
* User-settable options (used with setsockopt).
*/
#ifdef TCP_NODELAY
#undef TCP_NODELAY
#endif
#define	TCP_NODELAY	0x01	/* don't delay send to coalesce packets */

#ifdef TCP_MAXSEG
#undef TCP_MAXSEG
#endif
#define	TCP_MAXSEG	0x02	/* set maximum segment size */

/***************************************************************************************/
/*									L4_TCP - Interface								   */
/***************************************************************************************/

/*!
    \class	L4_TCP

    \brief	A 4 tcp.

    \sa	protosw
*/
class L4_TCP : public protosw 
{
public:

	/*!
	    \struct	tcphdr
	
	    \brief	TCP header.
	
	    \sa	Per RFC 793, September, 1981.
	*/
	struct tcphdr;

	/*!
	    \struct	tcpiphdr
	
	    \brief	TCP pseudo header: Tcp+ip header, after ip options removed.
	*/
	struct tcpiphdr;

	/*!
	    \class	tcpcb
	
	    \brief	Tcp control block, one per tcp.
	*/
	class tcpcb;

	/*!
	    \fn	L4_TCP::L4_TCP(class inet_os &inet)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	*/
	L4_TCP(class inet_os &inet) 
		: protosw(inet, SOCK_STREAM, NULL, IPPROTO_TCP, PR_CONNREQUIRED | PR_WANTRCVD) { }

	/*!
	    \pure	virtual void L4_TCP::pr_init() = 0;
	
	    \brief	Tcp initialization.
	*/
	virtual void pr_init() = 0;

	/*!
	    \pure	virtual void L4_TCP::pr_input(const struct pr_input_args &args) = 0;
	
	    \brief
	    TCP input routine, follows pages 65-76 of the protocol specification dated September,
	    1981 very closely.
	    
	    \par 
	    TCP input processing is the largest piece of code that we examine in this text. The
	    function tcp_input() is about 2000 lines of code. The processing of incoming segments is
	    not complicated, just long and detailed. Many implementations, including the one in Net/3,
	    closely follow the input event processing steps in RFC 793, which spell out in detail how
	    to respond to the various input segments, based on the current state of the connection.
	    
	    \par 
	    The tcp_input function is called by ip_input (through the pr_input function in the
	    protocol switch table) when a datagram is received with a protocol field of TCP.
	    tcp_input() executes at the software interrupt level.
	    
	    \par 
	    We first discusses the steps through RST processing, and next the ACK processing.
	    
	    \par 
	    The first few steps are typical: validate the input segment (checksum, length, etc.)
	    and locate the PCB for this connection. Given the length of the remainder of the function,
	    however, an attempt is made to bypass all this logic with an algorithm called header
	    prediction. This algorithm is based on the assumption that segments are not typically
	    lost or reordered, hence for a given connection TCP can often guess what the next
	    received segment will be. If the header prediction algorithm works, notice that the
	    function returns. This is the fast path through tcp_input.
	    
	    \par 
	    The slow path through the function ends up at the label dodata, which tests a few
	    flags and calls tcp_output if a segment should be sent in response to the received
	    segment.
	    
	    \par
	    There are also three functions that are called to when errors occur: dropafterack,
	    dropwithreset, and drop. The term drop means to drop the segment being processed, not
	    drop the connection, but when an RST is sent by dropwithreset it normally causes the
	    connection to be dropped.
	    
	    \par
	    The only other branching in the function occurs when a valid SYN is received in
	    either the LISTEN or SYN_SENT states, at the switch following header prediction. When the
	    code at trimthenstep6 finishes, it jumps to step6, which continues the normal flow.
	    
		\par
	    We test was that either the	ACK flag was set or, if not, the segment was dropped. The ACK
	    flag is handled, the window information is updated, the URG flag is processed, and any
	    data in the segment is processed. Finally the FIN flag is processed and tcp_output is
	    called, if required.
	    
		\par
	    We now explain ACK processing, in a summary. The SYN_RCVD state is handled specially,
	    followed by common processing for all remaining states. (Remember that a received ACK in
	    either the LISTEN or SYN_SENT state was already processed in the beginning.) This is
	    followed by special processing for the three states in which a received ACK causes a
	    state transition, and for the TIME_WAIT state, in which the receipt of an ACK causes the
	    2MSL timer to be restarted.
	
	    \param	args	The arguments, no need to inherit got it all in there.
	*/
	virtual void pr_input(const struct pr_input_args &args) = 0;

	/*!
	    \pure	virtual int L4_TCP::pr_output(const struct pr_output_args &args) = 0;
	
	    \brief
	    Tcp output routine: figure out what should be sent and send it.

	    \par
	    The function tcp_output is called whenever a segment needs to be sent on a connection.
	    There are numerous calls to this function from other TCP functions:
	    	a.	tcp_usrreq calls it for various requests: PRU_CONNECT to send the initial SYN,
	    		PRU_SHUTDOWN to send a FIN, PRU_RCVD in case a window update can be sent after the
	    		process has read some data from the socket receive buffer, PRU_SEND to send data, and
	    		PRU_SENDOOB to send out-of-band data.
	    	b.	tcp_fasttimo calls it to send a delayed ACK. 
			c.	tcp_tirners calls it to retransmit a segment when the retransmission timer
	    		expires.
	    	d.	tcp_tirners calls it to send a persist probe when the persist timer expires. e.
	    		tcp_drop calls it to send an RST. 
			e.	tcp_disconnect calls it to send a FIN. 
			f.	tcp_input calls it when output is required or when an immediate ACK should
	    		be sent.
	    	g.	tcp_input calls it when a pure ACK is processed by the header prediction
	    		code and there is more data to send. (A pure ACK is a segment without data that just
	    		acknowledges data.)
	    	h.	tcp_input: calls it when the third consecutive duplicate ACK is received, to
	    		send a single segment (the fast retransmit algorithm).
	    \par
	    tcp_output first determines whether a segment should be sent or not. TCP output is
	    controlled by numerous factors other than data being ready to send to the other end of
	    the connection. For example, the other end might be advertising a window of size 0 that
	    stops TCP from sending anything, the Nagle algorithm prevents TCP from sending lots of
	    small segments, and slow start and congestion avoidance limit the amount of data TCP can
	    send on a connection. Conversely, some functions set flags just to force tcp_output to
	    send a segment, such as the TF_ACKNOW flag that means an ACK should be sent immediately
	    and not delayed. If tcp_output decides not to send a segment, the data (if any) is left
	    in the socket's send buffer for a later call to this function.
	    
	    \param	args	The arguments (should implement an inheriting struct).
	
	    \return	An int, for error handling.
	*/
	virtual int pr_output(const struct pr_output_args &args) = 0;

	/*!
	    \pure virtual int L4_TCP::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;
	
	    \brief
	    TCP's user-request function is called for a variety of operations. Figure 30.1 shows the
	    beginning and end of tcp_usrreq. The body of the switch is shown in following figures.
	    The function arguments, some of which differ depending on the request, are described in
	    Figure 15.17. Process a TCP user request for TCP tb.  If this is a send request then m is
	    the mbuf chain of send data.  If this is a timer expiration (called from the software
	    clock routine), then timertype tells which timer.
	
	    \param [in,out]	so	   	If non-null, the socket that request something.
	    \param	req			   	The request to perform.
	    \param [in,out]	m	   	The std::shared_ptr<std::vector<byte>> to process, generally the input data.
	    \param [in,out]	nam	   	If non-null, the nam additional parameter, usually sockaddr.
	    \param	nam_len		   	Length of the nam.
	    \param [in,out]	control	The control (unused).
	
	    \return	An int.
	*/
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>> &m,
		struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;

	/*!
	    \pure	virtual void L4_TCP::pr_fasttimo() = 0;
	
	    \brief
	    The function is called by pffasttimo every 200 ms. It handles only the delayed ACK timer.
	    
	    \par 
	    Each Internet PCB on the TCP list that has a corresponding TCP control block is
	    checked. If the TF_DELACK flag is set, it is cleared and the TF_ACKNOW flag is set
	    instead. tcp_output is called, and since the TF_ACKNOW flag is set, an ACK is sent.
	    
	    \par 
	    How can TCP have an Internet PCB on its PCB list that doesn't have a TCP control
	    block (the test at line 50)? When a socket is created (the PRU_ATTACH request, in
	    response to the socket system call) we'll see that the creation of the Internet PCB is
	    done first, followed by the creation of the TCP control block. Between these two
	    operations a high-priority clock interrupt can occur, which calls tcp_fasttimo. Fast
	    timeout routine for processing delayed acks.
	*/
	virtual void pr_fasttimo() = 0;

	/*!
	    \pure	virtual void L4_TCP::pr_slowtimo() = 0;
	
	    \brief
	    The function tcp_slowtimo, is called by pfslowtimo every 500 ms. It handles the other six
	    TCP timers: connection establishment, retransmission, persist, keepalive, FIN_WAIT_2, and
	    2MSL.
	    
		\par
	    Tcp protocol timeout routine called every 500 ms. Updates the timers in all active tcb's
	    and causes finite state machine actions if timers expire. Pr slowtimo.
	*/
	virtual void pr_slowtimo() = 0;

protected:
	virtual void pr_drain() { }
	virtual int pr_sysctl() { return 0; }
	virtual void pr_ctlinput() { }
	virtual int pr_ctloutput() { return 0; }
};



/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

#include <iostream>
#include <fstream>


struct L4_TCP::tcphdr 
{
	/*!
	    \typedef	u_char_pack th_off_x2_pack
	
	    \brief
	    Defines an alias representing the two 4-bit pack of offset and x2, according to windows
	    byte order (BIG_ENDIAN).
	*/
	typedef u_char_pack th_off_x2_pack;

	/*!
	    \typedef	u_long tcp_seq
	
	    \brief	For BSD consistency.
	*/
	typedef	u_long		tcp_seq;

	/*!
	    \enum	TH_
	
	    \brief	Flags for TCP header.
	*/
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

	/*!
	    \fn	friend std::ostream& operator<<(std::ostream &out, const struct tcphdr &tcp);
	
	    \brief	Stream insertion operator.
	
	    \param [in,out]	out	The output stream (usually std::cout).
	    \param	tcp		   	The tcphdr to printout.
	
	    \return	The output stream, when #tcp was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream &out, const struct tcphdr &tcp);

	/*!
	    \brief	Gets the data offset.
	*/
	inline	const u_char th_off() const { return th_off_x2.hb; }
	
	/*!
	    \brief	Gets the unused.
	*/
	inline	const u_char th_x2() const { return th_off_x2.lb; }
	
	/*!
	    \brief	Sets the data offset.
	*/
	inline	void th_off(const u_char& th_off) { th_off_x2.hb = th_off; }
	
	/*!
	    \brief	Sets the unused.
	*/
	inline	void th_x2(const u_char& ip_hl) { th_off_x2.lb = ip_hl; }

	u_short	th_sport;		/*!< source port */
	u_short	th_dport;		/*!< destination port */
	tcp_seq	th_seq;			/*!< sequence number */
	tcp_seq	th_ack;			/*!< acknowledgment number */
	
	th_off_x2_pack th_off_x2;   /*!< data offset then unused */

	u_char	th_flags;   /*!< The flags \see TH_ */
	u_short	th_win;		/*!< window */
	u_short	th_sum;		/*!< checksum */
	u_short	th_urp;		/*!< urgent pointer */
};

struct L4_TCP::tcpiphdr 
{
	/*!
	    \typedef	u_long tcp_seq
	
	    \brief	For BSD consistency.
	*/
	typedef	u_long		tcp_seq;

	/*!
	    \struct	ipovly
	
	    \brief	Overlay for ip header used by other protocols (tcp, udp).
	*/
	struct ipovly 
	{
		/*!
		    \fn	ipovly()
		
		    \brief	Default constructor.
		*/
		ipovly();

		/*!
		    \fn
		    ipovly(const u_char& ih_pr, const short &ih_len, const in_addr &ih_src, const in_addr &ih_dst)
		
		    \brief	Constructor.
		
		\param	ih_pr	 	The ip header protocol.
		\param	ip_len   	The ip header parameter ip_len (total length).
		\param	ip_src   	The IP source address.
		\param	ip_dst   	The IP destination address.
		*/
		ipovly(const u_char& ih_pr, const short &ih_len, const in_addr &ih_src, const in_addr &ih_dst);

		/*!
		    \fn
		    friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr::ipovly &ip);
		
		    \brief	Stream insertion operator.
		
		    \param [in,out]	out	The output stream (usually std::cout).
		    \param	ip		   	The ipovly to printout.
		
		    \return	The output stream, when #ip was inserted and printed.
		*/
		friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr::ipovly &ip);

		struct L4_TCP::tcpiphdr	*ih_next, *ih_prev;			/*!< for protocol sequence q's */
		u_char	ih_x1 = 0x00;		/*!< (unused) */
		u_char	ih_pr;				/*!< protocol */
		short	ih_len;				/*!< protocol length */
		struct	in_addr ih_src;		/*!< source internet address */
		struct	in_addr ih_dst;		/*!< destination internet address */
	};
	
	/*!
	    \fn	tcpiphdr()
	
	    \brief	Default constructor.
	*/
	tcpiphdr();

	/*!
	    \fn
	    tcpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)
	
	    \brief	Constructor from received packet, does the casting.
	
	    \param [in,out]	m	If non-null, the byte to process.
	    \param	ih_pr	 	The ip header protocol.
	    \param	ip_len   	The ip header parameter ip_len (total length).
	    \param	ip_src   	The IP source address.
	    \param	ip_dst   	The IP destination address.
	*/
	tcpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst);

	/*!
	    \fn	friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr &ti)
	
	    \brief	Stream insertion operator.
	
	    \param [in,out]	out	The output stream (usually std::cout).
	    \param	ti		   	The tcphdr to printout.
	
	    \return	The output stream, when #tcp was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr &ti);

	inline	struct L4_TCP::tcpiphdr* ti_next() { return ti_i.ih_next; }
	inline	void ti_next(struct L4_TCP::tcpiphdr *ih_next) { ti_i.ih_next = ih_next; }

	inline	struct L4_TCP::tcpiphdr* ti_prev() { return ti_i.ih_prev; }

	inline	void ti_prev(struct L4_TCP::tcpiphdr *ih_prev) { ti_i.ih_prev = ih_prev; }
	
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
	
	inline	void ti_x2(const u_char& th_x2)	{ ti_t.th_x2(th_x2); }
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

	/*!
	    \fn
	    void tcp_template(const struct in_addr &inp_faddr, const u_short &inp_fport, const struct in_addr &inp_laddr, const u_short &inp_lport)
	
	    \brief
	    Create template to be used to send tcp packets on a connection. Call after host entry
	    created, allocates an mbuf and fills in a skeletal tcp/ip header, minimizing the amount
	    of work necessary when the connection is used.
	
	    \param	inp_faddr	The foreign host table entry
	    \param	inp_fport	The foreign port.
	    \param	inp_laddr	The local host table entry.
	    \param	inp_lport	The local port.
	*/
	void tcp_template(const struct in_addr &inp_faddr, const u_short &inp_fport, const struct in_addr &inp_laddr, const u_short &inp_lport);

	/*!
		\bug 
		Due to the use of smart pointers, which size is twice the size of a regular pointer,
		this function will not work as expected. In addition, casting smart pointers is very
		dangerous and should not be done at all!
		A better solution should be found.
		
	    \fn	inline std::shared_ptr<std::vector<byte>> REASS_MBUF()
	
	    \brief
	    We want to avoid doing m_pullup on incoming packets but that means avoiding dtom on the
	    tcp reassembly code.  That in turn means keeping an mbuf pointer in the reassembly queue
	    (since we might have a cluster).  As a quick hack, the source &amp; destination port
	    numbers (which are no longer needed once we've located the tcpcb) are overlayed with an
	    mbuf pointer.
	
	    \return	A std::shared_ptr<std::vector<byte>>
	*/
	inline std::shared_ptr<std::vector<byte>> REASS_MBUF();

	/*!
	    \fn	inline void insque(struct tcpiphdr &head)
	
	    \brief	Insert the given head to the global PCB linked list.
	
	    \param [in,out]	head	The head.
	*/
	inline void insque(struct tcpiphdr &head);

	/*!
	    \fn	inline void remque()
	
	    \brief
	    Remove this object from the linked list.
	    
	    \warning Does not delete the object!
	*/
	inline void remque();

	struct	ipovly ti_i;	/*!< overlaid ip structure */
	struct	tcphdr ti_t;	/*!< tcp header */
};


class L4_TCP::tcpcb	
	: public inpcb_impl 
{
	friend class L4_TCP_impl;
	friend class tcp_tahoe;
	friend class tcp_reno;

protected:
	/*!
	    \enum	TCPS_
	
	    \brief	TCP FSM state definitions.
	
	    \sa	Per RFC793, September, 1981.
	*/
	enum TCPS_
	{
		TCPS_CLOSED = 0,		/*!< closed */
		TCPS_LISTEN = 1,		/*!< listening for connection */
		TCPS_SYN_SENT = 2,		/*!< active, have sent syn */
		TCPS_SYN_RECEIVED = 3,	/*!< have send and received syn */
		
		/* states < TCPS_ESTABLISHED are those where connections not established */
		TCPS_ESTABLISHED = 4,	/*!< established */
		TCPS_CLOSE_WAIT = 5,	/*!< rcvd fin, waiting for close */
		
		/* states > TCPS_CLOSE_WAIT are those where user has closed */
		TCPS_FIN_WAIT_1 = 6,	/*!< have closed, sent fin */
		TCPS_CLOSING = 7,		/*!< closed xchd FIN; await FIN ACK */
		TCPS_LAST_ACK = 8,		/*!< had fin and close; await FIN ACK */
		
		/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
		TCPS_FIN_WAIT_2 = 9,	/*!< have closed, fin is acked */
		TCPS_TIME_WAIT = 10,	/*!< in 2*msl quiet wait after close */
		TCP_NSTATES = 11		/*!< The TCP number of states */
	};

	/*!
	    \enum	TF_
	
	    \brief	Flags for tcpcb
	*/
	enum TF_
	{
		TF_ACKNOW = 0x0001,		/*!< ack peer immediately */
		TF_DELACK = 0x0002,		/*!< ack, but try to delay it */
		TF_NODELAY = 0x0004,	/*!< don't delay packets to coalesce */
		TF_NOOPT = 0x0008,		/*!< don't use tcp options */
		TF_SENTFIN = 0x0010,	/*!< have sent FIN */
		TF_REQ_SCALE = 0x0020,	/*!< have/will request window scaling */
		TF_RCVD_SCALE = 0x0040,	/*!< other side has requested scaling */
		TF_REQ_TSTMP = 0x0080,	/*!< have/will request timestamps */
		TF_RCVD_TSTMP = 0x0100,	/*!< a timestamp was received in SYN */
		TF_SACK_PERMIT = 0x0200	/*!< other side said I could SACK */
	};

	/*!
	    \enum	TCPOOB_
	
	    \brief	Flags for TCP out-of-band.
	*/
	enum TCPOOB_
	{
		TCPOOB_HAVEDATA = 0x01,
		TCPOOB_HADDATA = 0x02
	};

	enum
	{
		TCPT_NTIMERS = 4	/*!< The tcpt number of timers */
	};

	/*!
	    \fn	explicit L4_TCP::tcpcb::tcpcb(inet_os &inet)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	*/
	explicit tcpcb(inet_os &inet);

	/*!
	    \fn	L4_TCP::tcpcb::tcpcb(socket &so, inpcb_impl &head);
	
	    \brief
	    Create a new TCP control block, making an empty reassembly queue and hooking it to the
	    argument protocol control block.
	
	    \param [in,out]	so  	The so.
	    \param [in,out]	head	The head.
	*/

	tcpcb(socket &so, inpcb_impl &head);

	~tcpcb();

	/*!
	    \fn	inline bool L4_TCP::tcpcb::TCPS_HAVERCVDSYN() const
	
	    \brief	Determines if we have received SYN.
	
	    \return	true if it succeeds, false if it fails.
	*/
	inline bool TCPS_HAVERCVDSYN() const;

	/*!
	    \fn	inline bool L4_TCP::tcpcb::TCPS_HAVERCVDFIN() const
	
	    \brief	Determines if we have received FIN.
	
	    \return	true if it succeeds, false if it fails.
	*/
	inline bool TCPS_HAVERCVDFIN() const;

	/*!
	    \fn	const u_char L4_TCP::tcpcb::tcp_outflags() const
	
	    \brief
	    Flags used when sending segments in tcp_output. Basic flags (TH_RST,TH_ACK,TH_SYN,TH_FIN)
	    are totally determined by state, with the proviso that TH_FIN is sent only if all data
	    queued for output is included in the segment.
	
	    \return	A flagged u_char.
	*/	
	inline const u_char tcp_outflags() const;

	/*!
	    \fn	static inline tcpcb* L4_TCP::tcpcb::intotcpcb(inpcb_impl *ip)
	
	    \brief	A tcpcb* caster from inpcb_impl.
	
	    \param [in,out]	ip	If non-null, the inpcb_impl to cast.
	
	    \return	null if it fails, else a tcpcb* casted version of #ip.
	*/
	static inline class L4_TCP::tcpcb* intotcpcb(class inpcb_impl *ip);
	static inline class L4_TCP::tcpcb* intotcpcb(class inpcb *ip);

	/*!
	    \fn	static inline tcpcb* L4_TCP::tcpcb::sototcpcb(socket *so)
	
	    \brief	A tcpcb* caster from socket.
	
	    \param [in,out]	so	If non-null, the socket to cast.
	
	    \return	null if it fails, else a tcpcb* casted version of the #so pcb.
	*/
	static inline class L4_TCP::tcpcb* sototcpcb(socket *so);

	/*!
	    \fn	template<typename T> static inline bool L4_TCP::tcpcb::SEQ_LT(T a, T b)
	
	    \brief	Sequence less than.
	
	    \tparam	T	Generic type parameter.
	    \param	a	The T to process.
	    \param	b	The T to process.
	
	    \return	true if it a < b, false if it fails.
	*/
	template<typename T>
	static inline bool SEQ_LT(T a, T b);

	/*!
	    \fn	template<typename T> static inline bool L4_TCP::tcpcb::SEQ_LEQ(T a, T b)
	
	    \brief	Sequence less than or equal.
	
	    \tparam	T	Generic type parameter.
	    \param	a	The T to process.
	    \param	b	The T to process.
	
	    \return	true if it a <= b, false if it fails.
	*/
	template<typename T>
	static inline bool SEQ_LEQ(T a, T b);

	/*!
	    \fn	template<typename T> static inline bool L4_TCP::tcpcb::SEQ_GT(T a, T b)
	
	    \brief	Sequence greater than.
	
	    \tparam	T	Generic type parameter.
	    \param	a	The T to process.
	    \param	b	The T to process.
	
	    \return	true if it a > b, false if it fails.
	*/
	template<typename T>
	static inline bool SEQ_GT(T a, T b);

	/*!
	    \fn	template<typename T> static inline bool L4_TCP::tcpcb::SEQ_GEQ(T a, T b)
	
	    \brief	Sequence greater than or equal.
	
	    \tparam	T	Generic type parameter.
	    \param	a	The T to process.
	    \param	b	The T to process.
	
	    \return	true if it a >= b, false if it fails.
	*/
	template<typename T>
	static inline bool SEQ_GEQ(T a, T b);

	/*!
	    \fn virtual tcpcb * in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags)
	
	    \brief	Calls inpcb_impl::in_pcblookup();
	
	    \param	faddr	 	The foreign host table entry.
	    \param	fport_arg	The foreign port.
	    \param	laddr	 	The local host table entry.
	    \param	lport_arg	The local port.
	    \param	flags	 	The flags \ref INPLOOKUP_.
	
	    \return	null if it fails, else the matching inpcb.
	*/
	virtual class L4_TCP::tcpcb* in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags);

	/*!
	    \fn	void L4_TCP::tcpcb::tcp_template()
	
	    \brief
	    Create template to be used to send tcp packets on a connection. Call after host entry
	    created, allocates an mbuf and fills in a skeletal tcp/ip header, minimizing the amount
	    of work necessary when the connection is used.
	*/
	void tcp_template();

	/*!
	    \fn	inline void L4_TCP::tcpcb::tcp_rcvseqinit()
	
	    \brief
	    Macros to initialize tcp sequence number for receive from initial receive sequence number.
	*/
	inline void tcp_rcvseqinit();

	/*!
	    \fn	inline void L4_TCP::tcpcb::tcp_sendseqinit()
	
	    \brief	Macros to initialize tcp sequence number for send from initial send sequence number.
	*/
	inline void tcp_sendseqinit();

	/*!
	    \fn	inline void L4_TCP::tcpcb::tcp_quench()
	
	    \brief
	    When a source quench is received, close congestion window to one segment.  We will
	    gradually open it again as we proceed.
	*/
	inline void tcp_quench();

	/*!
	    \fn	inline short L4_TCP::tcpcb::TCP_REXMTVAL() const;
	
	    \brief
	    The initial retransmission should happen at rtt + 4 * rttvar. Because of the way we do
	    the smoothing, srtt and rttvar will each average +1/2 tick of bias.  When we compute the
	    retransmit timer, we want 1/2 tick of rounding and 1 extra tick because of +-1/2 tick
	    uncertainty in the firing of the timer.  The bias will give us exactly the 1.5 tick we
	    need.  But, because the bias is statistical, we have to test that we don't drop below the
	    minimum feasible timer (which is 2 ticks). This macro assumes that the value of
	    TCP_RTTVAR_SCALE is the same as the multiplier for rttvar.
	
	    \return	A short.
	*/
	inline short TCP_REXMTVAL() const;

	/*!
	    \fn	void L4_TCP::tcpcb::tcp_xmit_timer(short rtt);
	
	    \brief	Collect new round-trip time estimate and update averages and current timeout.
	
	    \param	rtt	The rtt.
	*/
	void tcp_xmit_timer(short rtt);

	/*!
	    \fn	void L4_TCP::tcpcb::tcp_canceltimers();
	
	    \brief
	    Cancel all timers for TCP tp. The function tcp_canceltimers, shown in Figure 25.6, is
	    called by tcp_input when the TIME_ WAIT state is entered. All four timer counters are set
	    to 0, which turns off the retransmission, persist, keepalive, and FIN_WAIT_2 timers,
	    before tcp_input sets the 2MSL timer.
	*/
	void tcp_canceltimers();

	void log_snd_cwnd(u_long snd_cwnd);


	struct	tcpiphdr *seg_next;	/*!< sequencing queue next */
	struct	tcpiphdr *seg_prev;	/*!< sequencing queue prev */
	
	short	t_state;			/*!< state of this connection */
	
	short	t_timer[TCPT_NTIMERS];	/*!< tcp timers */
	short	t_rxtshift;	/*!< log(2) of rexmt exp. backoff */
	short	t_rxtcur;	/*!< current retransmit value */
	short	t_dupacks;	/*!< consecutive dup acks recd */
	
	u_short	t_maxseg;	/*!< maximum segment size */
	char	t_force;	/*!< 1 if forcing out a byte */
	
	u_short	t_flags;	/*!< Flags \see TF_ */
	
	struct	tcpiphdr	*t_template;	/*!< skeletal packet for transmit */
	
	class	inpcb_impl	*t_inpcb;	/*!< back pointer to internet pcb */

	/*
	* The following fields are used as in the protocol specification.
	* See RFC783, Dec. 1981, page 21.
	*/
	/* send sequence variables */
	tcp_seq	snd_una;		/*!< send unacknowledged */
	tcp_seq	snd_nxt;		/*!< send next */
	tcp_seq	snd_up;			/*!< send urgent pointer */
	tcp_seq	snd_wl1;		/*!< window update seg seq number */
	tcp_seq	snd_wl2;		/*!< window update seg ack number */
	tcp_seq	iss;			/*!< initial send sequence number */
	u_long	snd_wnd;		/*!< send window */
	
	/* receive sequence variables */
	u_long	rcv_wnd;		/*!< receive window */
	tcp_seq	rcv_nxt;		/*!< receive next */
	tcp_seq	rcv_up;			/*!< receive urgent pointer */
	tcp_seq	irs;			/*!< initial receive sequence number */
	
	/* Additional variables for this implementation. */
	/* receive variables */
	tcp_seq	rcv_adv;		/*!< advertised window */
	
	/* retransmit variables */
	tcp_seq	snd_max;		/*!< highest sequence number sent; used to recognize retransmits */
	
	/* congestion control (for slow start, source quench, retransmit after loss) */
	u_long	snd_cwnd;		/*!< congestion-controlled window */
	u_long	snd_ssthresh;	/*!< snd_cwnd size threshold for for slow start exponential to linear switch */
	
	/* 
	 * transmit timing stuff.  See below for scale of srtt and rttvar.
	 * "Variance" is actually smoothed difference.
	 */
	u_short	t_idle;			/*!< inactivity time */
	short	t_rtt;			/*!< round trip time */
	tcp_seq	t_rtseq;		/*!< sequence number being timed */
	short	t_srtt;			/*!< smoothed round-trip time */
	short	t_rttvar;		/*!< variance in round-trip time */
	u_short	t_rttmin;		/*!< minimum rtt allowed */
	u_long	max_sndwnd;		/*!< largest window peer has offered */

	/* out-of-band data */
	char	t_oobflags;		/*!< have some */
	char	t_iobc;			/*!< input character \see TCPOOB_*/
	short	t_softerror;	/*!< possible error not yet reported */

	/* RFC 1323 variables */
	u_char	snd_scale;			/*!< window scaling for send window */
	u_char	rcv_scale;			/*!< window scaling for recv window */
	u_char	request_r_scale;	/*!< pending window scaling reciever */
	u_char	requested_s_scale;  /*!< pending window scaling send */
	u_long	ts_recent;			/*!< timestamp echo data */
	u_long	ts_recent_age;		/*!< when last updated */
	tcp_seq	last_ack_sent;		/*!< The last acknowledge sent */

	/* TUBA stuff */
	char	*t_tuba_pcb;		/*!< next level down pcb for TCP over z */

	class tcpcb_logger {
		friend class L4_TCP::tcpcb;
	public:
		~tcpcb_logger()	{ log.close(); }
	protected:
		typedef std::chrono::duration<double> seconds;
		tcpcb_logger();
		tcpcb_logger(const tcpcb_logger&)
		{
			//tcpcb_logger();
		}
		
		void update(u_long snd_cwnd);

		std::ofstream log;
		std::chrono::time_point<std::chrono::high_resolution_clock> start;
		static int log_number;
	};

	tcpcb_logger log;
};