#ifndef NETLAB_L4_UDP_H
#define NETLAB_L4_UDP_H

#include "L3.h"
#include "pcb.h"

class L4_UDP : public protosw {
public:

	/*!
		\struct	udphdr

		\brief	UDP header.

		\sa	Per RFC 768, August, 1980.
	*/
	struct udphdr;

	/*!
		\struct	udpiphdr

		\brief	UDP pseudo header: UDP + IP header, after ip options removed.
	*/
	struct udpiphdr;

	/*!
		\class	udpcb

		\brief	UDP control block, one per UDP.
	*/
	class udpcb;

	/*!
		\fn	L4_UDP::L4_UDP(class inet_os &inet)

		\brief	Constructor.

		\param [in,out]	inet	The inet.
	*/
	L4_UDP(class inet_os& inet)
		: protosw(inet, SOCK_DGRAM, NULL, IPPROTO_UDP, PR_ATOMIC & PR_ADDR) { }  // DETERMINE FLAGS !

	/*!
		\pure	virtual void L4_UDP::pr_init() = 0;

		\brief	UDP initialization.
	*/
	virtual void pr_init() = 0;

	/*!
		\pure	virtual void L4_UDP::pr_initt(const struct pr_input_args& args) = 0;

		\brief	UDP initialization.
	*/
	virtual void pr_input(const struct pr_input_args& args) = 0;

	/*!
		\pure	virtual int L4_UDP::pr_output(const struct pr_output_args &args) = 0;

		\brief
		UDP output routine: figure out what should be sent and send it.
	*/

	virtual int pr_output(const struct pr_output_args& args) = 0;

	/*!
		\pure virtual int L4_TCP::pr_usrreq(class netlab::socket *so, int req, std::shared_ptr<std::vector<byte>> &m, struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) = 0;

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
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) = 0;
};


/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

#include <iostream>
#include <fstream>


struct L4_UDP::udphdr
{

	/*!
	 
		\brief Definition of the UDP's header parts.	

		\param	src_port_number	 	Two bytes used to represent the source port number.
		\param	dst_port_number   	Two bytes used to represent the destination port number.
		\param	udp_datagram_length   	Two bytes used to represent the length of the UDP datagram (header + data).
		\param	udp_checksum   	Two bytes used to represent the checksum of the UDP datagram.
	*/

	 u_short src_port_number;
	 u_short dst_port_number;
	 u_short udp_datagram_length;
	 u_short udp_checksum;

	 udphdr()
		 : src_port_number(0), dst_port_number(0), udp_datagram_length(0), udp_checksum(0) {}

	/*!
		\fn	friend std::ostream& operator<<(std::ostream &out, const struct udphdr &udp);

		\brief	Stream insertion operator.

		\param [in,out]	out	The output stream (usually std::cout).
		\param	tcp		   	The udphdr to printout.

		\return	The output stream, when #udp was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream& out, const struct udphdr& udp);

};

struct L4_UDP::udpiphdr {

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

		struct L4_UDP::udpiphdr* ih_next, * ih_prev;			/*!< for protocol sequence q's */
		u_char	ih_x1 = 0x00;		/*!< (unused) */
		u_char	ih_pr;				/*!< protocol */
		short	ih_len;				/*!< protocol length */
		struct	in_addr ih_src;		/*!< source internet address */
		struct	in_addr ih_dst;		/*!< destination internet address */
	};

	struct	ipovly ti_i;	/*!< Overlaid ip structure */
	struct	udphdr ti_u;	/*!< UDP header */

	/*!
		\fn	udpiphdr()

		\brief	Default constructor.
	*/
	udpiphdr();

	/*!
		\fn
		udpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)

		\brief	Constructor from received packet, does the casting.

		\param [in,out]	m	If non-null, the byte to process.
		\param	ih_pr	 	The ip header protocol.
		\param	ip_len   	The ip header parameter ip_len (total length).
		\param	ip_src   	The IP source address.
		\param	ip_dst   	The IP destination address.
	*/

	udpiphdr(byte* m, const u_char& ih_pr, const short& ip_len, const in_addr& ip_src, const in_addr& ip_dst);
	
	/*!
		\fn	friend std::ostream& operator<<(std::ostream &out, const struct udpiphdr &ti)

		\brief	Stream insertion operator.

		\param [in,out]	out	The output stream (usually std::cout).
		\param	ti		   	The udphdr to printout.

		\return	The output stream, when #udp was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream& out, const struct udpiphdr& ti);

	inline	struct L4_UDP::udpiphdr* ti_next() { return ti_i.ih_next; }
	inline	void ti_next(struct L4_UDP::udpiphdr* ih_next) { ti_i.ih_next = ih_next; }

	inline	struct L4_UDP::udpiphdr* ti_prev() { return ti_i.ih_prev; }
	inline	void ti_prev(struct L4_UDP::udpiphdr* ih_prev) { ti_i.ih_prev = ih_prev; }

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

	inline  u_short& ti_seq() { return ti_u.src_port_number; }
	inline	const u_short& ti_seq() const { return ti_u.src_port_number; }

	inline  u_short& ti_seq() { return ti_u.dst_port_number; }
	inline	const u_short& ti_seq() const { return ti_u.dst_port_number; }

	inline  u_short& ti_seq() { return ti_u.udp_datagram_length; }
	inline	const u_short& ti_seq() const { return ti_u.udp_datagram_length; }

	inline u_short& ti_seq() { return ti_u.udp_checksum; }
	inline const u_short& ti_seq() const { return ti_u.udp_checksum;  }

	/*!
		\fn
		void udp_template(const struct in_addr &inp_faddr, const u_short &inp_fport, const struct in_addr &inp_laddr, const u_short &inp_lport)

		\brief
		Create template to be used to send UDP packets on a connection. Call after host entry
		created, allocates an mbuf and fills in a skeletal UDP/IP header, minimizing the amount
		of work necessary when the connection is used.

		\param	inp_faddr	The foreign host table entry
		\param	inp_fport	The foreign port.
		\param	inp_laddr	The local host table entry.
		\param	inp_lport	The local port.
	*/
	void udp_template(const struct in_addr& inp_faddr, const u_short& inp_fport, const struct in_addr& inp_laddr, const u_short& inp_lport);

	/*!
		\fn	inline void insque(struct tcpiphdr &head)

		\brief	Insert the given head to the global PCB linked list.

		\param [in,out]	head	The head.
	*/
	inline void insque(struct udphdr & head);

	/*!
		\fn	inline void remque()

		\brief
		Remove this object from the linked list.

		\warning Does not delete the object!
	*/
	inline void remque();

};


#endif