#pragma once

#include "../L2/L2.h"
#include "../L3/L3.h"
#include "../infra/pcb.h"
#include "boost/range.hpp"

/*******************************************************************************************************/
/*										 L4_UDP - INTERFACE											   */
/*******************************************************************************************************/

class L4_UDP : public protosw {
public:

/************************************************************************/
/*                         L4_UDP_Impl::udphdr                          */
/************************************************************************/

	struct udphdr {

		/*
			Definition of the UDP's header parts.
				* uh_sport - Two bytes used to represent the source port number.
				* uh_dport - Two bytes used to represent the destination port number.
				* uh_ulen - Two bytes used to represent the length of the UDP datagram (header + data).
				* uh_sum - Two bytes used to represent the checksum of the UDP datagram.
		*/

		u_short uh_sport;
		u_short uh_dport;
		u_short uh_ulen;
		u_short uh_sum;

		udphdr()
			: uh_sport(0), uh_dport(0), uh_ulen(0), uh_sum(0) {}

		// Stream insertion operator.
		friend std::ostream& operator<<(std::ostream& out, const struct udphdr& udp);
	};

	struct udpiphdr;

	// Constructor - UDP control block, one per UDP.
	class udpcb;

	L4_UDP(class inet_os& inet);

	// UDP initialization.
	virtual void pr_init() = 0;

	// UDP input routine: figure out what should be sent and send it.
	virtual void pr_input(const struct pr_input_args& args) = 0;

	// pr output routine : figure out what should be sent and send it (wrapper for udp_output).
	virtual int pr_output(const struct pr_output_args& args) = 0;

	/*
		pr_usrreq Function - TCP's user-request function is called for sending data over UDP.
			* so - If non-null, the socket that request something.
			* req - The request to perform (always send data in the case of UDP).
			* m - The std::shared_ptr<std::vector<byte>> to process, generally the input data.
			* nam - If non-null, the nam additional parameter, usually sockaddr.
			* nam_len - Length of the nam.
			* control - The control (unused).
	*/
	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) = 0;

/************************************************************************/
/*                         L4_UDP_Impl::udp_output_args                 */
/************************************************************************/

	struct udp_output_args : public pr_output_args {
		/*
			udp_output_args Function - The constructor.
				* m - The std::shared_ptr<std::vector<byte>> to process.
				* it - The iterator, maintaining the current offset in the vector.
		*/
		udp_output_args(udpcb& up);

		udpcb& up;
	};

private:
	/* Unused - protosw virtual functions */
	virtual void pr_drain() { }
	virtual void pr_fasttimo() { }
	virtual void pr_slowtimo() { }
	virtual int pr_sysctl() { return 0; }
	virtual void pr_ctlinput() { }
	virtual int pr_ctloutput() { return 0; }
};

class L4_UDP::udpcb : public inpcb_impl {

	friend class L4_UDP_Impl;

private:

	// Constructor.
	explicit udpcb(inet_os& inet);

	/*
		Constructor -
		Create a new UDP control block, making an empty reassembly queue and hooking it to the
		argument protocol control block.
			* so - The socket.
			* head - The head.
	*/
	udpcb(socket& so, inpcb_impl& head);

	// Destructor.
	~udpcb();

	/*
		intoudpcb Function - A udpcb* caster from inpcb_impl.
			* ip - If non-null, the inpcb_impl to cast.
	*/
	static inline class L4_UDP::udpcb* intoudpcb(class inpcb_impl* ip) { return dynamic_cast<class L4_UDP::udpcb*>(ip); };
	static inline class L4_UDP::udpcb* intoudpcb(class inpcb* ip) { return dynamic_cast<class L4_UDP::udpcb*>(ip); } ;

	/*
		sotoudpcb Function - A udpcb* caster from socket.
			* so - If non-null, the socket to cast.
	*/
	static inline class L4_UDP::udpcb* sotoudpcb(socket* so) { return dynamic_cast<L4_UDP::udpcb*>(so->so_pcb); } 

	/*
		udp_template Function - 
		Create template to be used to send UDP packets on a connection. Call after host entry
		created, allocates an mbuf and fills in a skeletal UDP/IP header, minimizing the amount
		of work necessary when the connection is used.
	*/
	void udp_template();


	struct	udpiphdr *udp_ip_template;	/* Skeletal packet for transmit */
	class	inpcb_impl *udp_inpcb;	/* Back pointer to internet pcb */

	class udpcb_logger {
		friend class L4_UDP::udpcb;
	public:
		~udpcb_logger() { log.close(); }
	private:
		typedef std::chrono::duration<double> seconds;
		udpcb_logger() {};
		udpcb_logger(const udpcb_logger&) {}

		void update(u_long snd_cwnd);

		std::ofstream log;
		std::chrono::time_point<std::chrono::high_resolution_clock> start;
		static int log_number;
	};

	udpcb_logger log;
};