#pragma once

#include <iostream>
#include <fstream>
#include "L4_UDP.hpp"

class L4_UDP_Impl : public L4_UDP {
public:

/************************************************************************/
/*                         L4_UDP_Impl::udphdr                          */
/************************************************************************/

	struct udphdr {

		/*!

		\brief Definition of the UDP's header parts.

		\param	uh_sport	 	Two bytes used to represent the source port number.
		\param	uh_dport   	Two bytes used to represent the destination port number.
		\param	uh_ulen   	Two bytes used to represent the length of the UDP datagram (header + data).
		\param	uh_sum   	Two bytes used to represent the checksum of the UDP datagram.
		*/

		u_short uh_sport;
		u_short uh_dport;
		u_short uh_ulen;
		u_short uh_sum;

		udphdr()
			: uh_sport(0), uh_dport(0), uh_ulen(0), uh_sum(0) {}

		/*!
			\fn	friend std::ostream& operator<<(std::ostream &out, const struct udphdr &udp);

			\brief	Stream insertion operator.

			\param [in,out]	out	The output stream (usually std::cout).
			\param	tcp		   	The udphdr to printout.

			\return	The output stream, when #udp was inserted and printed.
		*/
		friend std::ostream& operator<<(std::ostream& out, const struct udphdr& udp);
	};

/************************************************************************/
/*                         L4_UDP_Impl::udpiphdr                        */
/************************************************************************/

	struct udpiphdr {

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
			ipovly(const u_char& ih_pr, const short& ih_len, const in_addr& ih_src, const in_addr& ih_dst);

			/*!
				\fn
				friend std::ostream& operator<<(std::ostream &out, const struct tcpiphdr::ipovly &ip);

				\brief	Stream insertion operator.

				\param [in,out]	out	The output stream (usually std::cout).
				\param	ip		   	The ipovly to printout.

				\return	The output stream, when #ip was inserted and printed.
			*/
			friend std::ostream& operator<<(std::ostream& out, const struct udpiphdr::ipovly& ip);

			struct L4_UDP_Impl::udpiphdr* ih_next, * ih_prev;			/*!< for protocol sequence q's */
			u_char	ih_x1 = 0x00;		/*!< (unused) */
			u_char	ih_pr;				/*!< protocol */
			short	ih_len;				/*!< protocol length */
			struct	in_addr ih_src;		/*!< source internet address */
			struct	in_addr ih_dst;		/*!< destination internet address */
		};

		/*!
			\fn
			udpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)

			\brief	Constructor from received packet, does the casting.

			\param [in,out]	m		If non-null, the byte to process.
			\param	protocol	 	The ip header protocol.
			\param	udp_length   	The udp header parameter udp_length (total length).
			\param	ip_src_addr   	The IP source address.
			\param	ip_dst_addr   	The IP destination address.
		*/

		/*!
			\fn udpiphdr()
			
			\brief Default constructor.
		*/

		udpiphdr();

		/*!
		\fn	friend std::ostream& operator<<(std::ostream &out, const struct udphdr &ui)

		\brief	Stream insertion operator.

		\param [in,out]	out	The output stream (usually std::cout).
		\param	ui		   	The udphdr to printout.

		\return	The output stream, when #udp was inserted and printed.
	*/
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

		/*!
		\fn	inline void insque(struct udpiphdr &head)

		\brief	Insert the given head to the global PCB linked list.

		\param [in,out]	head	The head.
	*/
		inline void insque(struct udpiphdr& head);

		/*!
			\fn	inline void remque()

			\brief
			Remove this object from the linked list.

			\warning Does not delete the object!
		*/
		inline void remque();

		struct ipovly ui_i;
		struct udphdr ui_u;
	};

/************************************************************************/
/*                         L4_UDP_Impl									*/
/************************************************************************/

	typedef class netlab::L5_socket_impl socket;

	/*!
		\fn	L4_UDP_Impl::L4_UDP_Impl(class inet_os &inet)

		\brief	Constructor.

		\param [in,out]	inet	The inet.
	*/

	L4_UDP_Impl(class inet_os &inet);

	/*!
		\fn	L4_UDP_Impl::~L4_UDP_Impl()

		\brief	Deletes the UDP object.
	*/

	~L4_UDP_Impl();

	/*!
		\pure	virtual void L4_UDP::pr_init() override;

		\brief	UDP initialization.
	*/

	virtual void pr_init() override;

	/*!
		\pure	virtual void L4_UDP::pr_input(const struct pr_input_args& args) override;

		\brief	UDP input routine: figure out what should be sent and send it.
	*/
	virtual void pr_input(const struct pr_input_args& args) override;

	/*!
		\fn	void L4_UDP_Impl::drop(class inpcb_impl *inp, const int dropsocket);

		\brief
		Drop UDP socket.

		\param [in,out]	inp	If non-null, the inp holding the socket to abort.
		\param	dropsocket 	The dropsocket.
	*/

	inline void drop(class inpcb_impl* inp, const int dropsocket);

	static inline int out(udpcb& up, int error);

	inline int udp_attach(socket& so);

	/*!
		\pure	virtual int L4_UDP::pr_output(const struct pr_output_args &args) override;

		\brief
		UDP output routine: figure out what should be sent and send it.
	*/

	virtual int pr_output(const struct pr_output_args& args) override;

	/*!
		\fn	int L4_UDP_Impl::udp_output(udpcb &up);

		\brief	The actual function, with the desired arguments.

		\note
		Most of the work is done by again, this separation was in order to avoid gotos.

		\param [in,out]	up	The udpcb of this connection.

		\return	An int, for error handling.
	*/

	inline int udp_output(udpcb &up);

	/*!
		\pure virtual int L4_TCP::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) override;

		\brief
		TCP's user-request function is called for sending data over UDP.

		\param [in,out]	so	   	If non-null, the socket that request something.
		\param	req			   	The request to perform (always send data in the case of UDP).
		\param [in,out]	m	   	The std::shared_ptr<std::vector<byte>> to process, generally the input data.
		\param [in,out]	nam	   	If non-null, the nam additional parameter, usually sockaddr.
		\param	nam_len		   	Length of the nam.
		\param [in,out]	control	The control (unused).

		\return	An int.
	*/

	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) override;


/************************************************************************/
/*                         L4_UDP_Impl::udp_output_args                 */
/************************************************************************/

	struct udp_output_args
		: public pr_output_args
	{
		/*!
			\fn	udp_output_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, struct L3::route *ro, int flags, struct L3::ip_moptions *imo);

			\brief	Constructor.

			\param [in,out]	m  	The std::shared_ptr<std::vector<byte>> to process.
			\param [in,out]	it 	The iterator, maintaining the current offset in the vector.
		*/
		udp_output_args(udpcb &up);

		udpcb& up;
	};

	

private:

		uint16_t calculate_checksum(udpiphdr& udp_pseaudo_header, std::shared_ptr<std::vector<byte>>& m);

		class L4_UDP::udpcb udb;
		class inpcb_impl* udp_last_inpcb;

		u_long	udp_sendspace;   /*!< The UDP send space */
		u_long	udp_recvspace;   /*!< The UDP recv space */

};


