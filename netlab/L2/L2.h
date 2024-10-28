/*!
	\file	L2.h

	\author	Tom Mahler

	\brief	Declares the 2 class.
*/
#pragma once

/*!
	\def	NETLAB_L2_DEBUG
	Define in order to printout the L2 packets for debug
*/
//#define NETLAB_L2_DEBUG

#include "../L3/L3.h"
#include "../L1/NIC.h"

struct rtentry;

/*!
    \class	L2

    \brief
    Represents a Layer 2 interface (Ethernet).
    
    \pre	First initialize an instance of inet_os.
    \pre	Must define struct L2::ether_header.
*/
class L2 {
public:

	/*!
	    \struct	ether_header
	
	    \brief
	    Structure of a 10Mb/s Ethernet header. The Ethernet device driver is responsible for
	    converting ether_type between network and host byte order. Outside of the driver, it is
	    always in host byte order.
	    
	    \note The Ethernet CRC is not generally available. It is computed and checked by the
	    interface hardware, which discards frames that arrive with an invalid CRC.
	*/
	struct ether_header;

	/*!
	    \fn	L2::L2(class inet_os &inet)
	
	    \brief	Constructs an L2 interface.
	
	    \param [in,out]	inet	The inet.
	*/
	L2(class inet_os &inet);

	/*!
	    \brief	L2 destructor, updates its #inet that the interface is deleted.
	*/
	virtual ~L2();

	/*!
	    \pure virtual void L2::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt) = 0;
	
	    \brief
	    We now examine the output of Ethernet frames, which starts when a network-level protocol
	    such as IP calls the \ref inet_os ether_output function, specified in the \ref inet_os
	    nic class. The output function for all Ethernet devices is ether_output (Figure 4.2).
	    ether_output takes the data portion of an Ethernet frame, encapsulates it with the 14-
	    byte Ethernet header, and places it on the interface's send queue. This is a large which
	    sums into four parts:
	    	a.	verification, 
			b.	protocol-specific processing, 
			c.	frame construction, and 
			d.	interface queuing.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it		The iterator, as the current offset in the vector.
	    \param [in,out]	dst	the destination address of the packet.
	    \param [in,out]	rt 	routing information.
	*/
	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt) = 0;

	/*!
	    \pure	virtual void L2::ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) = 0;
	
	    \brief
	    Process a received Ethernet packet. This method is called by the \ref NIC::leread(). It
	    unwraps the Ethernet header of the received data, drops invalid packets, passes the
	    unwraped data to the correct upper interface (i.e ARP and IP in our case) and possibly
	    prints relevant information.
	
	    \param [in,out]	m 	The received data.
	    \param [in,out]	it	The iterator, as the current offset in the vector.
	    \param [in,out]	eh	pointer to a casted \ref ethernet_header
	*/
	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) = 0;

protected:
	class inet_os &inet; /*!< The inet_os owning this protocol. */
}; // L2

/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

class L2_impl : public L2
{
public:

	/*!
	    \fn	L2_impl::L2_impl(class inet_os &inet)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	*/
	L2_impl(class inet_os &inet);

	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt);

	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh);

protected:

	NIC* getNIC() { return inet.nic(); }



}; // L2_impl

