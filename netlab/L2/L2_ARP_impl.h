#pragma once

#include "L2_ARP.h"

/**********************************************************************************/
/*							   L2_ARP - Solution                                  */
/**********************************************************************************/

typedef std::map<u_long, std::shared_ptr<L2_ARP::llinfo_arp>> ARP_map;

class L2_ARP_impl
	: public L2_ARP
{
public:

	/*
		Constructor
			* inet - reference to the inet_os object - initiate the ArpCache.
			* arp_maxtries - The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs).
			* arpt_down - The arp timeout for an entry.
	*/
	explicit L2_ARP_impl(class inet_os& inet, const unsigned long arp_maxtries = 10, const int arpt_down = 10000);

	/*
		arprequest Function The arprequest function is called by arpresolve to send an ARP request.
		 * m - The std::shared_ptr<std::vector<byte>> to process.
		 * it - The iterator to m.
		 * mflags - The flags.
		 * dst - The destination.
	*/
	inline virtual mac_addr* arpresolve(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, short m_flags, struct sockaddr* dst);

	/*
		in_arpinput Function The in_arpinput function is called by the ARP input routine when a packet is received.
		 * m - The std::shared_ptr<std::vector<byte>> to process.
		 * it - The iterator to m.
	*/
	inline virtual void in_arpinput(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

	/*
		insertPermanent Function The insertPermanent function is called by the ARP input routine when a packet is received.
		 * ip - The ip.
		 * la_mac - The la mac.
	*/
	inline virtual void insertPermanent(const u_long ip, const mac_addr& la_mac);

private:

	/* 
		arpwhohas Function The arpwhohas function is normally called by arpresolve to broadcast an ARP request.
			* addr - The IP address.
	*/
	inline void arpwhohas(const struct in_addr& addr);
	
	/*
		arprequest Function The arprequest function is called by arpresolve to send an ARP request.
			* tip - The target IP.
	*/
	inline virtual void arprequest(const u_long& tip);

	/*
		arplookup Function The arplookup function is called by arpresolve to lookup an ARP entry.
			* addr - The IP address.
			* create - The create flag.
	*/
	inline virtual std::shared_ptr<L2_ARP::llinfo_arp> arplookup(const u_long addr, bool create);

	/*
		SendArpReply Function The SendArpReply function is called by arpresolve to send an ARP reply.
			* itaddr - The itaddr.
			* isaddr - The isaddr.
			* hw_tgt - The hw tgt.
			* hw_snd - The hw snd.
	*/
	inline virtual void SendArpReply(const struct in_addr& itaddr, const struct in_addr& isaddr, const mac_addr& hw_tgt, const mac_addr& hw_snd) const;

	// An ARP cache table, using std map.
	class ArpCache : public ARP_map
	{
	public:

		// Definition of key type.
		typedef std::map < u_long, std::shared_ptr<L2_ARP::llinfo_arp> > _Myt;

		/*
			Constructor
				* arp_maxtries - The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs).
				* arpt_down - The arp timeout for an entry.
		*/
		explicit ArpCache(const unsigned long arp_maxtries = 10, const unsigned int arpt_down = 10000);

		/*
			operator[] Function - The operator[] function is used to access the element with the specific key.
				* k - The key.
		*/
		mapped_type& operator[] (const key_type& k);
		mapped_type& operator[] (key_type&& k);

		/*
			find Function - Searches for the first match for the given constant key type.
				* _Keyval - The keyval.
		*/
		inline iterator find(const key_type& _Keyval);

	private:

		// Cleanups the table if incounter old entery.
		inline void		cleanup();

		unsigned long	arp_maxtries;   /* The arp max tries before resend, default is 10 (once declared down, don't send for 10 secs). */
		unsigned int	arpt_down;		/* The arp timeout for an entry. */
	};

	class ArpCache		arpcache;   /* The arpcache */
};