#pragma once

#include <iostream>
#include <fstream>
#include "L4_UDP.hpp"

/*******************************************************************************************************/
/*										 L4_UDP - IMPLEMENTATION									   */
/*******************************************************************************************************/

class L4_UDP_Impl : public L4_UDP {
public:

/*******************************************************************************************************/
/*******************************************************************************************************/
/*				STUDENT IMPLEMENTATION SECTION BELOW - THE REST IS IMPLEMENTED FOR YOU				   */
/*******************************************************************************************************/
/*******************************************************************************************************/

	// UDP input routine: figure out what should be sent and send it.
	virtual void pr_input(const struct pr_input_args& args) override;

	
	// pr output routine: figure out what should be sent and send it (wrapper for udp_output).
	virtual int pr_output(const struct pr_output_args& args) override;

	/*
		udp_output Function - The actual function, with the desired arguments.
			* up - The UDP control block of this connection (used to get the socket).
	*/
	inline int udp_output(udpcb& up);

/*******************************************************************************************************/
/*******************************************************************************************************/
/*				STUDENT IMPLEMENTATION SECTION ABOVE - THE REST IS IMPLEMENTED FOR YOU				   */
/*******************************************************************************************************/
/*******************************************************************************************************/




/************************************************************************/
/************************************************************************/




/************************************************************************/
/*                         L4_UDP_Impl::udpiphdr                        */
/************************************************************************/

	struct udpiphdr {

		struct ipovly
		{
			// Default constructor.
			ipovly();

			/*
				ipovly Function - Constructor.
					* ih_pr - The ip header protocol.
					* ih_len - The ip header parameter ip_len (total length).
					* ih_src - The IP source address.
					* ih_dst - The IP destination address.
			*/
			ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst);

			// Stream insertion operator.
			friend std::ostream& operator<<(std::ostream& out, const struct udpiphdr::ipovly& ip);

			struct L4_UDP_Impl::udpiphdr* ih_next, * ih_prev;			/* For protocol sequence q's */
			u_char	ih_x1 = 0x00;		/* (unused) */
			u_char	ih_pr;				/* Protocol */
			short	ih_len;				/* Protocol length */
			struct	in_addr ih_src;		/* Source internet address */
			struct	in_addr ih_dst;		/* Destination internet address */
		};

		/*
			udpiphdr Function - Constructor from received packet, does the casting.
				* m - If non-null, the byte to process.
				* ih_pr - The ip header protocol.
				* ih_len - The udp header parameter udp_length (total length).
				* ih_src - The IP source address.
				* ih_dst - The IP destination address.
		*/
		udpiphdr();

		// Stream insertion operator.
		friend std::ostream& operator<<(std::ostream& out, const struct udpiphdr& ui);

		inline	struct L4_UDP_Impl::udpiphdr* ui_next() { return ui_i.ih_next; }
		inline	void ui_next(struct L4_UDP_Impl::udpiphdr* ih_next) { ui_i.ih_next = ih_next; }

		inline	struct L4_UDP_Impl::udpiphdr* ui_prev() { return ui_i.ih_prev; }
		inline	void ui_prev(struct L4_UDP_Impl::udpiphdr* ih_prev) { ui_i.ih_prev = ih_prev; }

		inline	u_char& ui_x1() { return ui_i.ih_x1; }
		inline	const u_char& ui_x1() const { return ui_i.ih_x1; }

		inline	u_char& ui_pr() { return ui_i.ih_pr; }
		inline	const u_char& ui_pr() const { return ui_i.ih_pr; }

		inline	short& ui_len() { return ui_i.ih_len; }
		inline	const short& ui_len() const { return ui_i.ih_len; }

		inline	struct	in_addr& ui_src() { return ui_i.ih_src; }
		inline	const struct	in_addr& ui_src() const { return ui_i.ih_src; }

		inline	struct	in_addr& ui_dst() { return ui_i.ih_dst; }
		inline	const struct	in_addr& ui_dst() const { return ui_i.ih_dst; }

		inline	u_short& ui_sport() { return ui_u.uh_sport; }
		inline	const u_short& ui_sport() const { return ui_u.uh_sport; }

		inline	u_short& ui_dport() { return ui_u.uh_dport; }
		inline	const u_short& ui_dport() const { return ui_u.uh_dport; }

		inline	u_short& ui_sum() { return ui_u.uh_sum; }
		inline	const u_short& ui_sum() const { return ui_u.uh_sum; }

		inline	u_short& ui_ulen() { return ui_u.uh_ulen; }
		inline	const short& ui_ulen() const { return ui_u.uh_ulen; }

		// Insert the given head to the global PCB linked list.
		inline void insque(struct udpiphdr& head);

		// Remove this object from the linked list.
		inline void remque();

		struct ipovly ui_i;
		struct udphdr ui_u;
	};

/************************************************************************/
/*                         L4_UDP_Impl									*/
/************************************************************************/

	typedef class netlab::L5_socket_impl socket;

	// Constructor
	L4_UDP_Impl(class inet_os &inet);

	// Destructor.
	~L4_UDP_Impl();


	// UDP initialization.
	virtual void pr_init() override;

	/*
		drop Function - drop UDP socket.
			* inp - If non-null, the inp holding the socket to abort.
			* dropsocket - The dropsocket.
	*/
	inline void drop(class inpcb_impl* inp, const int dropsocket);

	static inline int out(udpcb& up, int error);

	inline int udp_attach(socket& so);

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
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) override;

private:
		class L4_UDP::udpcb udb;
		class inpcb_impl* udp_last_inpcb;

		u_long	udp_sendspace;   /* The UDP send space */
		u_long	udp_recvspace;   /* The UDP recv space */
};