#pragma once

#include "../L1/NIC.h"
#include "../infra/inet_os.hpp"

/**********************************************************************************/
/*							   L2_ARP - Interface                                 */
/**********************************************************************************/

class L2_ARP {
public:

	// Defines an alias representing the MAC address.
	typedef netlab::HWAddress<> mac_addr;

	// ARP packets are variable in size; the arphdr structure defines the fixed-length portion.
	struct	ether_arp;

	// One llinfo_arp structure, exists for each ARP entry.
	class llinfo_arp;

	/* Constructor
		* inet_os - the inet_os owning this protocol.
		* arp_maxtries - the arp max tries before resend, default is 10 (once declared down, don't send for 10 secs).
		* arpt_down - the arp timeout for an entry.
	*/
	explicit L2_ARP(class inet_os &inet, const unsigned long arp_maxtries = 10, const int arpt_down = 10000)
		: inet(inet), arp_maxtries(arp_maxtries), arpt_down(arpt_down) { inet.arp(this); }

	// Destructor
	~L2_ARP() { inet.arp(nullptr); }

	/*
		arpresolve Function: ether_output() calls arpresolve() to obtain the Ethernet address for
	    an IP address.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator.
			* m_flags - The flags.
			* dst - a pointer to a sockaddr_in containing the destination IP address.
	*/
	virtual mac_addr* arpresolve(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, short m_flags, struct sockaddr *dst) = 0;

	/*
		in_arpinput Function: ARP for Internet protocols on 10 Mb/s Ethernet. Algorithm is that given in RFC 826.
			* m - The std::shared_ptr<std::vector<byte>> to process.
			* it - The iterator.
	*/
	virtual void in_arpinput(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) = 0;

	/*
		insertPermanent Function: Inserts a permanent arp entry, useful for debugging.
			* ip - The IP.
			* la_mac - The la MAC.
	*/
	virtual void insertPermanent(const u_long ip, const mac_addr &la_mac) = 0;

	// Gets arp maxtries.
	const unsigned long getArpMaxtries() const { return arp_maxtries; }

	// Gets arpt_down.
	const unsigned int getArptDown() const{ return arpt_down; }			/* once declared down, don't send for 10 secs */
	
protected:

	/*
		arpresolve Function: ether_output() calls arpresolve() to obtain the Ethernet address for
		an IP address.
			* m - The std::shared_ptr<std::vector<byte>> to process./
			* it - The iterator.
			* m_flags - The flags.
			* dst - a pointer to a sockaddr_in containing the destination IP address.
	*/
	virtual void arprequest(const u_long &tip) = 0;

	/*
		arplookup Function: Look up an ARP entry.
			* addr - The address.
			* create - true to create.
	*/ 
	virtual std::shared_ptr<L2_ARP::llinfo_arp> arplookup(const u_long addr, bool create) = 0;

	/*
		sendArpReply Function: Send an ARP Reply.
			* itaddr - The target ip address.
			* isaddr - The sender ip address.
			* hw_tgt - The target hardware (MAC) address.
			* hw_snd - The sender hardware (MAC) address.
	*/
	virtual void SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const = 0;

	class inet_os	&inet;			/* The inet_os owning this protocol. */

private:
	unsigned long	arp_maxtries;   /* The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs). */
	unsigned int	arpt_down;		/* The arp timeout for an entry. */
};

/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

#include <map>

struct	L2_ARP::ether_arp 
{
	// Defines an alias representing the MAC address.
	typedef netlab::HWAddress<> mac_addr;

	// The arphdr structure defines the fixed-length portion.
	struct	arphdr 
	{
		// Values that represent arphrds (Using only #ARPHRD_ETHER).
		enum ARPHRD_
		{
			ARPHRD_ETHER = 1,	/* Ethernet hardware format */
			ARPHRD_FRELAY = 15	/* Frame relay hardware format */
		};

		// Values that represent arp operations.
		enum ARPOP_
		{
			ARPOP_REQUEST = 1,		/* Request to resolve address */
			ARPOP_REPLY = 2,		/* Response to previous request */
			ARPOP_REVREQUEST = 3,	/* Request protocol address given hardware */
			ARPOP_REVREPLY = 4,		/* Response giving protocol address */
			ARPOP_INVREQUEST = 8, 	/* Request to identify peer */
			ARPOP_INVREPLY = 9		/* Response identifying peer */
		};

		// Constructor from ARPOP_, other values are 0.
		explicit arphdr(ARPOP_ op = ARPOP_REQUEST);

		// Returns the string representing the object's arp operation for printouts.
		inline std::string ar_op_format() const;

		inline std::string hw_addr_format() const;

		inline friend std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp::arphdr &ea_hdr);

		u_short	ar_hrd;		/* Format of hardware address */
		u_short	ar_pro;		/* Format of protocol address */
		u_char	ar_hln;		/* Length of hardware address */
		u_char	ar_pln;		/* Length of protocol address */
		u_short	ar_op;		/* One of ARPOP_ */
	};

	// Gets the arp's header format of hardware address.
	inline u_short& arp_hrd() { return ea_hdr.ar_hrd; }

	// Gets the arp's header format of protocol address.
	inline	u_short& arp_pro() { return ea_hdr.ar_pro; }

	// Gets the arp's header length of hardware address.
	inline	u_char& arp_hln() { return ea_hdr.ar_hln; }

	// Gets the arp's header length of protocol address.
	inline	u_char& arp_pln() { return ea_hdr.ar_pln; }

	// Gets the arp's header arp operation.
	inline	u_short& arp_op() { return ea_hdr.ar_op; }

	/*
		Full Constructor, arphdr is default-constructed from the op.
			* tip - The target ip.
			* sip - The source IP.
			* taddr - The target hw addr.
			* saddr - The source hw addr.
			* op - The arp operation	
	*/
	ether_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, arphdr::ARPOP_ op = arphdr::ARPOP_REQUEST);

	/*
		make_arp Function: Makes an arp packet (without the ether_header, however allocates the place to hold one).
			* tip - The target ip.
			* sip - The source IP.
			* taddr - The target hw addr.
			* saddr - The source hw addr.
			* it - The iterator to return.
			* op - The arp operation.
	*/
	inline static std::shared_ptr<std::vector<byte>> make_arp(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it, arphdr::ARPOP_ op = arphdr::ARPOP_REQUEST);

	/*
		make_arp_request Function: Makes an arp request packet (without the ether_header, however allocates the place to hold one).
			* tip - The target ip.
			* sip - The source IP.
			* taddr - The target hw addr.
			* saddr - The source hw addr.
			* it - The iterator to return.
	*/
	inline static std::shared_ptr<std::vector<byte>> make_arp_request(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it);

	/*
		make_arp_reply Function: Makes an arp reply packet (without the ether_header, however allocates the place to hold one).
			* tip - The target ip.
			* sip - The source IP.
			* taddr - The target hw addr.
			* saddr - The source hw addr.
			* it - The iterator to return.
	*/ 
	inline static std::shared_ptr<std::vector<byte>> make_arp_reply(const u_long tip, const u_long sip, mac_addr taddr, mac_addr saddr, std::vector<byte>::iterator &it);

	/*
		Stream insertion operator.
			* out - The output stream (usually std::cout).
			* ea - The ether_arp to printout.
	*/
	inline friend std::ostream& operator<<(std::ostream &out, const struct L2_ARP::ether_arp &ea);

	struct	arphdr ea_hdr;		/* Fixed-size header */
	mac_addr	arp_sha;		/* Sender hardware address */
	u_char		arp_spa[4];		/* Sender protocol address */
	mac_addr	arp_tha;		/* Target hardware address */
	u_char		arp_tpa[4];		/* Target protocol address */
};

class L2_ARP::llinfo_arp
{
public:
	
	// Constructor
	explicit llinfo_arp(bool permanent = false);

	/* 
		Constructor 
			* la_mac - The la MAC.
			* permanent - true to permanent.
	*/
	explicit llinfo_arp(const mac_addr &la_mac, bool permanent = false);

	// Destructor
	inline ~llinfo_arp();

	// Checks if the entry is valid in terms of time.
	inline bool valid() const;

	// Gets la MAC (non-const).
	inline mac_addr& getLaMac();

	/*	
		clearToSend Function: Checks if the entry is clear to send.
			* arp_maxtries - The arp_maxtries (supplied by L2_ARP).
			* arpt_down - The arpt_down (supplied by L2_ARP).
	*/
	inline bool clearToSend(const unsigned long arp_maxtries, const unsigned int arpt_down);

	// Removes the top-of-stack packet, la_hold and its corresponding iterator hold_it.
	inline void pop();

	/*
		push Function: Pushes a packet, la_hold and its corresponding iterator hold_it onto this stack.
			* hold - The packet to hold.
			* hold_it - The iterator of the packet to hold.
	*/
	inline void push(std::shared_ptr<std::vector<byte>> hold, const std::vector<byte>::iterator hold_it);

	// Gets the top-of-stack packet, la_hold.
	inline std::shared_ptr<std::vector<byte>> front() const;

	// Gets the top-of-stack, iterator.
	inline std::vector<byte>::iterator& front_it();

	// Tests if the stack (of la_hold) is empty.
	inline bool empty() const;

	// Updates the entry with the given la_mac.
	inline void update(const mac_addr la_mac);

	// Gets la timestamp.
	inline unsigned long long getLaTimeStamp() const;

private:
	enum time_stamp
	{
		MAX_TIME_STAMP = 10000	/*	25 minutes	*/
	}; 

	mac_addr							la_mac;		/* The la MAC address */
	std::shared_ptr<std::vector<byte>>	la_hold;	/* Last packet until resolved/timeout */
	std::vector<byte>::iterator 		la_hold_it;	/* The la hold iterator, as the current offset in the vector. */

	unsigned long			la_asked;		/* Number of times we've queried for this addr */
	unsigned short			la_flags;		/* Last time we QUERIED for this addr */
	unsigned long long		la_timeStamp;	/* Last time we QUERIED for this addr */
};