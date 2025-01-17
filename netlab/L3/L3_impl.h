#pragma once

#include "L3.h"

/********************************************************************************************/
/*										SOLUTION											*/
/********************************************************************************************/

/************************************************************************/
/*							L3_impl class								*/
/************************************************************************/

class L3_impl : public L3
{
public:

	// Defines an alias representing the short as received from the net.
	typedef u_short n_short;

	// Defines an alias representing the long as received from the net.
	typedef u_long	n_long;

	//Defines an alias representing the time in ms since 00:00 GMT, byte rev. 
	typedef	u_long	n_time;

	// Defines different types of IP necessities. 
	enum ip_things
	{
		IPVERSION = 4,					/* Definitions for internet protocol version 4. Per RFC 791, September 1981 */
		MAX_IPOPTLEN = 40,				/* The actual length of the options (including ipopt_dst). */
		IP_MAX_MEMBERSHIPS = 20,		/* Per socket; must fit in one mbuf (legacy) */
		IP_MAXPACKET = 65535,			/* The maximum packet size */
		IP_MSS = 576,					/* The default maximum segment size */
		IP_DEFAULT_MULTICAST_TTL = 1	/* Normally limit multi casts to 1 hop */
	};

	// Definitions for options.
	enum IPOPT_
	{
		IPOPT_EOL = 0,			/* End of option list */
		IPOPT_NOP = 1,			/* No operation */
		IPOPT_RR = 7,			/* Record packet route */
		IPOPT_TS = 68,			/* Timestamp */
		IPOPT_SECURITY = 130,	/* Provide s,c,h,tcc */
		IPOPT_LSRR = 131,		/* Loose source route */
		IPOPT_SATID = 136,		/* Satnet id */
		IPOPT_SSRR = 137,		/* Strict source route */

		/*
		* Offsets to fields in options other than EOL and NOP.
		*/
		IPOPT_OPTVAL = 0,		/* Option ID */
		IPOPT_OLEN = 1,			/* Option length */
		IPOPT_OFFSET = 2,		/* Offset within option */
		IPOPT_MINOFF = 4		/* Min value of above */
	};

	// Security Options for Internet Protocol (IPSO) as defined in RFC 1108.
	enum IPOPT_SECUR_
	{
		IPOPT_SECUR_UNCLASS = 0x0000,   /* The Security Options for Unclassified option */
		IPOPT_SECUR_CONFID = 0xf135,	/* The Security Options for Confidential option */
		IPOPT_SECUR_EFTO = 0x789a,		/* The Security Options for EFTO option */
		IPOPT_SECUR_MMMM = 0xbc4d,		/* The Security Options for MMMM option */
		IPOPT_SECUR_RESTR = 0xaf13,		/* The The Security Options for RESTR option */
		IPOPT_SECUR_SECRET = 0xd788,	/* The The Security Options for Secret option */
		IPOPT_SECUR_TOPSECRET = 0x6bc5  /* The The Security Options for Top Secret option */
	};

	// Internet implementation parameters for Time-To-Live.
	enum TTL_
	{
		MAXTTL = 255,		/* Maximum time to live (seconds) */
		IPDEFTTL = 64,		/* Default ttl, from RFC 1340 */
		IPFRAGTTL = 60,		/* Time to live for frags, slowhz */
		IPTTLDEC = 1		/* Subtracted when forwarding */
	};

	// Flags passed to ip_output as last parameter.
	enum IP_OUTPUT_
	{
		IP_FORWARDING = 0x1,				/* Most of ip header exists */
		IP_RAWOUTPUT = 0x2,					/* Raw ip header exists */
		IP_ROUTETOIF = SO_DONTROUTE,		/* Bypass routing tables */
		IP_ALLOWBROADCAST = SO_BROADCAST	/* Can send broadcast packets */
	};

	struct rt_metrics {

		// Constructor
		rt_metrics();

		u_long	rmx_locks;		/* Kernel must leave these values alone */
		u_long	rmx_mtu;		/* MTU for this path */
		u_long	rmx_hopcount;   /* Max hops expected */
		u_long	rmx_expire;		/* Lifetime for route, e.g. redirect */
		u_long	rmx_recvpipe;   /* Inbound delay-bandwith product */
		u_long	rmx_sendpipe;   /* Outbound delay-bandwith product */
		u_long	rmx_ssthresh;   /* Outbound gateway buffer limit */
		u_long	rmx_rtt;		/* Estimated round trip time */
		u_long	rmx_rttvar;		/* Estimated rtt variance */
		u_long	rmx_pksent;		/* Packets sent using this route */
	};

	// A route addrinfo.
	struct rt_addrinfo {

		// Index offsets for sockaddr array for alternate internal encoding.
		enum RTAX_
		{
			RTAX_DST = 0,		/* Destination sockaddr present */
			RTAX_GATEWAY = 1,	/* Gateway sockaddr present */
			RTAX_NETMASK = 2,	/* Netmask sockaddr present */
			RTAX_GENMASK = 3,	/* Cloning mask sockaddr present */
			RTAX_IFP = 4,		/* Interface name sockaddr present */
			RTAX_IFA = 5,		/* Interface addr sockaddr present */
			RTAX_AUTHOR = 6,	/* Sockaddr for author of redirect */
			RTAX_BRD = 7,		/* For NEWADDR, broadcast or p-p dest addr */
			RTAX_MAX = 8		/* Size of array to allocate */
		};

		int	rti_addrs;							/* The rti addrs */
		struct sockaddr* rti_info[RTAX_MAX];	/* The rti info[rtax max] array */
	};

	// Structures for routing messages.
	struct rt_msghdr {

		// Defines an alias representing the process id.
		typedef	int32_t	pid_t;

		u_short	rtm_msglen;			/* To skip over non-understood messages */
		u_char	rtm_version;		/* Future binary compatibility */
		u_char	rtm_type;			/* Message type */
		u_short	rtm_index;			/* Index for associated ifp */
		int	rtm_flags;				/* Flags, including kern & message, e.g. DONE */
		int	rtm_addrs;				/* Bitmask identifying sockaddrs in msg */
		pid_t	rtm_pid;			/* Identify sender */
		int	rtm_seq;				/* For sender to identify action */
		int	rtm_errno;				/* Why failed */
		int	rtm_use;				/* From rtentry */
		u_long	rtm_inits;			/* Which metrics we are initializing */
		struct	rt_metrics rtm_rmx; /* Metrics themselves */
	};

	// Annotations to tree concerning potential routes applying to subtrees.
	struct radix_mask {

		// Gets the rm_mask.
		inline char* rm_mask() const { return rm_rmu.rmu_mask; }

		// Gets rm_leaf.
		inline struct radix_node* rm_leaf() const { return rm_rmu.rmu_leaf; }

		short	rm_b;						/* Bit offset; -1-index(netmask) */
		char	rm_unused;					/* cf. rn_bmask */
		u_char	rm_flags;					/* cf. rn_flags */
		struct	radix_mask* rm_mklist;		/* More masks to try */

		union {
			char* rmu_mask;					/* The mask */
			struct	radix_node* rmu_leaf;	/* For normal routes */
		}	rm_rmu;

		int	rm_refs;						/* Number of references to this struct */
	};

	// Radix search tree node layout.
	struct radix_node {

		// Flags for #rn_flags.
		enum RNF_
		{
			RNF_NORMAL = 1,	/* Leaf contains normal route */
			RNF_ROOT = 2,	/* Leaf is root leaf for tree */
			RNF_ACTIVE = 4	/* This node is alive (for rtfree) */
		};

		// Constructor
		radix_node();

		// Gets rn_dupedkey.
		inline struct radix_node* rn_dupedkey() const { return rn_u.rn_leaf.rn_Dupedkey; }

		// Gets rn_key.
		inline char* rn_key() const { return rn_u.rn_leaf.rn_Key; }

		// Gets rn_mask.
		inline char* rn_mask() const { return rn_u.rn_leaf.rn_Mask; }

		// Gets rn_off.
		inline int& rn_off() { return rn_u.rn_node.rn_Off; }

		// Gets rn_l.
		inline struct radix_node* rn_l() const { return rn_u.rn_node.rn_L; }

		// Gets rn_r.
		inline struct radix_node* rn_r() const { return rn_u.rn_node.rn_R; }

		struct	radix_mask* rn_mklist;	/* List of masks contained in subtree */
		struct	radix_node* rn_p;		/* Parent */

		short	rn_b;					/* Bit offset; -1-index(netmask) */
		char	rn_bmask;				/* Node: mask for bit test*/
		u_char	rn_flags;				/* Enumerated above */

		union {
			struct {								/* Leaf only data: */
				char* rn_Key;						/* Object of search */
				char* rn_Mask;						/* Netmask, if present */
				struct	radix_node* rn_Dupedkey;	/* The rn dupedkey */
			} rn_leaf;
			struct {								/* Node only data: */
				int	rn_Off;							/* Where to start compare */
				struct	radix_node* rn_L;			/* Progeny */
				struct	radix_node* rn_R;			/* Progeny */
			} rn_node;
		}		rn_u;
	};

	// A radix node head.
	struct radix_node_head {
		struct L3_impl::radix_node* rnh_treetop;	/* The rnh treetop */
		int	rnh_addrsize;							/* Permit, but not require fixed keys */
		int	rnh_pktsize;							/* Permit, but not require fixed keys */
	};

	/* We need to save the IP options in case a protocol wants to respond to an incoming packet
		over the same route if the packet got here using IP source routing.  This allows
		connection establishment and maintenance when the remote end is on a network that is not
		known to us. */
	struct ip_srcrt {
		struct	in_addr dst;											/* Final destination */
		char	nop;													/* One NOP to align */
		char	srcopt[IPOPT_OFFSET + 1];								/* OPTVAL, OLEN and OFFSET */
		struct	in_addr route[MAX_IPOPTLEN / sizeof(struct in_addr)];   /* The route address array */
	};

	// Structure stored in mbuf in inpcb::ip_options and passed to ip_output when ip options are in use.
	struct ipoption {
		struct	in_addr ipopt_dst;			/* First-hop dst if source routed */
		char	ipopt_list[MAX_IPOPTLEN];	/* Options proper */
	};

	// IP Time stamp option structure.
	struct	ip_timestamp {

		// Defines an alias representing the two 4-bit pack of overflow counter then flags, according to windows byte order(BIG_ENDIAN).
		typedef u_char_pack ipt_oflw_flg_pack;

		// Flag bits for ipt_flg.
		enum IPOPT_TS_
		{
			IPOPT_TS_TSONLY = 0,	/* Timestamps only */
			IPOPT_TS_TSANDADDR = 1,	/* Timestamps and addresses */
			IPOPT_TS_PRESPEC = 3	/* Specified modules only */
		};

		u_char	ipt_code;				/* IPOPT_TS */
		u_char	ipt_len;				/* Size of structure (variable) */
		u_char	ipt_ptr;				/* Index of current entry */
		ipt_oflw_flg_pack ipt_oflw_flg; /* Overflow counter then flags defined in #IPOPT_TS_ */

		// An ipt timestamp.
		union ipt_timestamp {
			n_long	ipt_time[1];		 /* Network format */
			struct	ipt_ta {
				struct in_addr ipt_addr; /* The ipt address */
				n_long ipt_time;		 /* Network format */
			} ipt_ta[1];
		} ipt_timestamp;
	};

	typedef struct ip_fragment
	{
		std::shared_ptr<std::vector<byte>> frag_data;
		ip_fragment* next_fragment;

		ip_fragment(std::shared_ptr<std::vector<byte>> m) : frag_data(m), next_fragment(nullptr) { }
	}ip_fragment;


	/* IP reassembly queue structure.  Each fragment being reassembled is attached to one of
		these structures. They are timed out after ipq_ttl drops to 0, and may also be reclaimed
		if memory becomes tight. */
	struct ipq {
		enum ifq_len
		{
			IFQ_MAXLEN = 50			/* The ifq maxlen */
		};

		struct	ipq* next;			/* To other reassembly headers, forward */
		struct	ipq* prev;			/* To other reassembly headers, backward */
		u_char	ipq_ttl;			/* Time for reassembly q to live */
		u_char	ipq_p;				/* Protocol of this fragment */
		u_short	ipq_id;				/* Sequence id for reassembly */
		struct	ipasfrag* ipq_next;	/* The ip reassembly queue as linked list, forward */
		struct	ipasfrag* ipq_prev;	/* The ip reassembly queue as linked list, backward */
		struct	in_addr ipq_src;	/* To ip headers of fragments, source address */
		struct	in_addr ipq_dst;	/* To ip headers of fragments, destination address */
		ip_fragment* fragments;
		uint16_t total_length;
	};

	// IP header, when holding a fragment.
	struct	ipasfrag {

		// Defines an alias representing the two 4-bit pack of version and header length, according to windows byte order(BIG_ENDIAN).
		typedef u_char_pack ip_v_hl_pack;

		ip_v_hl_pack ip_v_hl;		/* Version then header length, in a ip_v_hl_pack. \note The IP header length is in 4-bytes unit */
		u_char	ipf_mff;			/* Copied from (ip_off&IP_MF)	\bug overlays ip_tos: use low bit to avoid destroying tos; */
		short	ip_len;				/* Total length, including data */
		u_short	ip_id;				/* Identification */
		short	ip_off;				/* Fragment offset field \see IP_ */
		u_char	ip_ttl;				/* Time to live */
		u_char	ip_p;				/* Protocol */
		u_short	ip_sum;				/* Checksum */
		struct	ipasfrag* ipf_next;	/* Next fragment */
		struct	ipasfrag* ipf_prev;	/* Previous fragment */
	};

	// Arguments for IP output.
	struct ip_output_args : public pr_output_args
	{

		/*
			Constructor
				* m - The std::shared_ptr<std::vector<byte>> to process.
				* it - The iterator, maintaining the current offset in the vector.
				* opt - The IP option \warning Must be std::shared_ptr<std::vector<byte>>(nullptr) as options are not supported.
				* ro - The route for the packet. Should only use the ro_dst member to hold the sockaddr for the output route.
				* flags - The flags.
				* imo - The IP multicast options \warning Must be nullptr as multicast are not supported.
		*/
		ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, std::shared_ptr<std::vector<byte>>& opt, struct L3::route* ro, int flags, struct  L3::ip_moptions* imo);

		std::shared_ptr<std::vector<byte>>& m;		/* The std::shared_ptr<std::vector<byte>> to process. */
		std::vector<byte>::iterator& it;			/* The iterator, maintaining the current offset in the vector. */
		std::shared_ptr<std::vector<byte>>& opt;	/* The IP option \warning Must be std::shared_ptr<std::vector<byte>>(nullptr) as options are not supported. */
		struct L3::route* ro;						/* The route for the packet. Should only use the ro_dst member to hold the sockaddr for the output route. */
		int flags;									/* The flags \see IP_OUTPUT_. */
		struct  L3::ip_moptions* imo;				/* The IP multicast options \warning Must be nullptr as multicast are not supported. */
	};

	/*
		Constructor
			* inet - The inet_os owning this protocol.
			* pr_type - The type of the protocol.
			* pr_protocol - The protocol number.
			* pr_flags - The flags of the protocol.
	*/
	L3_impl(class inet_os& inet, const short& pr_type = 0, const short& pr_protocol = 0, const short& pr_flags = 0);

	/*
		ip_insertoptions - insert IP options into preformed packet. Adjust IP destination as required for IP source
		routing, as indicated by a non-zero in_addr at the start of the options.

		Arguments:
			m - The std::shared_ptr<std::vector<byte>> to strip.
			it - The iterator, as the current offset in the vector.
			opt - The IP option to be inserted.
			phlen - The ip header length.

	*/
	static void ip_insertoptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, std::shared_ptr<std::vector<byte>>& opt, int& iphlen);

	/*
		ip_strippotions - Strip out IP options, at higher level protocol in the kernel.

		Arguments:
			m - The std::shared_ptr<std::vector<byte>> to strip.
			it - The iterator, as the current offset in the vector.
	*/
	static void ip_stripoptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

	// pr_init - Initialize the protocol.
	virtual void pr_init();

	// pr_input - Process a received IP datagram.
	virtual void pr_input(const struct pr_input_args& args);

	// pr_output - Output IP datagram.
	virtual int pr_output(const struct pr_output_args& args);

private:

	/*
		Fill in IP protocol switch table, and all protocols not implemented in kernel go to raw
		IP protocol handler. The ip_init function is called once by inet_os::domaininit(const
		bool start_timer). at system initialization time.
	*/
	void ip_init();

	/*
		The IP output code receives packets from two sources: the transport protocols and
		ip_forward() (which is disabled). For the standard Internet transport protocols, the
		generality of the protosw structure is not necessary, since the calling functions are not
		accessing IP in a protocol-independent context, however in order to allow different
		layers to be used, we access IP output operations to be accessed by inetsw[0].pr_output.
		We describe ip_output in three sections:
			*	header initialization,
			*	route selection, and
			*	source address selection and fragmentation.

		Arguments:
			args	 (ip_output_args).

	*/
	inline int ip_output(const struct ip_output_args& args);

	/*
		done - Helper function for ip_output(), frees the rtentry of ro.

		Arguments:
			ro		- The route from which to free the rtentry.
			iproute - The iproute.
			flags	- The flags.
			error	- The error to return.
	*/
	inline int done(struct route* ro, struct route& iproute, const int& flags, const int error);


	/*
		Note - Currently disabled.

		Do option processing on a datagram, possibly discarding it if bad options are encountered,
		or forwarding it if source-routed. Returns 1 if packet has been forwarded/freed, 0 if the
		packet should be processed further.

		Arguments:
			m	- The std::shared_ptr<std::vector<byte>> to strip.
			it	- The iterator, as the current offset in the vector.
	*/
	inline int ip_dooptions(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it);

	/*
		Note - Currently disabled.

		Forward a packet. If some error occurs return the sender an icmp packet. Note we can't
		always generate a meaningful icmp message because icmp doesn't have a large enough
		repertoire of codes and types.

		If not forwarding, just drop the packet. This could be confusing if ipforwarding was
		zero but some routing protocol was advancing us as a gateway to somewhere.  However, we
		must let the routing protocol deal with that.

		The srcrt parameter indicates whether the packet is being forwarded via a source route.

		Arguments:
			m		- The std::shared_ptr<std::vector<byte>> to strip.
			it		- The iterator, as the current offset in the vector.
			srcrt	- The srcrt.
	*/
	inline void ip_forward(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, const int& srcrt);

	/*!
		pr_input() helper for reassemble.

		Arguments:
			m		- The std::shared_ptr<std::vector<byte>> to strip.
			it		- The iterator, as the current offset in the vector.
			ip		- The \ref iphdr.
			hlen	- The hlen.
	*/
	inline void ours(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, struct iphdr& ip, int& hlen);

	/*!
		Prints the iphdr with checksum as its ip_sum, making sure to use the lock_guard for the print_mutex.

		Arguments:
			ip		- The iphdr.
			checksum - The checksum.
			str		- The string.
	*/
	inline void print(struct iphdr& ip, uint16_t checksum, std::ostream& str = std::cout);

	/*!
		Calculates the 16-bit checksum of the #buff of length #len.

		Note -  This routine is very heavily used in the network code and should be modified for
		each CPU to be as fast as possible.

		Note -  This implementation is 386 version.

		Arguments:
			buff	- The buffer to checksum.
			len		- The length.
	*/
	inline uint16_t in_cksum(const byte* buff, size_t len) { return inet.in_cksum(buff, len); }


	u_short	ip_id;						/* Last ID assigned to an outgoing IP packet */
	u_char	ip_protox[IPPROTO_MAX];		/* Demultiplexing array for IP packets */
	struct ipq ipq_t;					/* The reassembly queue */

	virtual void pr_drain() { };
	virtual int pr_sysctl() { return 0; };
	virtual void pr_ctlinput() { };
	virtual int pr_ctloutput() { return 0; };
	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>& m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>>& control) {
		return 0;
	};
	virtual void pr_fasttimo() { };
	virtual void pr_slowtimo() { };
};

/*!

	Structure of an internet header, naked of options. We declare ip_len and ip_off to be short,
	rather than u_short pragmatically since otherwise unsigned comparisons can result against
	negative integers quite easily, and fail in subtle ways.

	Note - Defined for the sake of consistency.
*/
struct L3::iphdr {

	/* Defines an alias representing the two 4-bit pack of version and header length, according
		to windows byte order (BIG_ENDIAN). */
	typedef struct u_char_pack ip_v_hl_pack;

	// Flags for ip_tos.
	enum IPTOS_
	{
		IPTOS_LOWDELAY = 0x10,				/* The ip_tos lowdelay option */
		IPTOS_THROUGHPUT = 0x08,			/* The ip_tos throughput option */
		IPTOS_RELIABILITY = 0x04,			/* The ip_tos reliability option */
		IPTOS_PREC_NETCONTROL = 0xe0,		/* The ip_tos prec netcontrol option (hopefully unused) */
		IPTOS_PREC_INTERNETCONTROL = 0xc0,  /* The ip_tos prec internetcontrol option (hopefully unused) */
		IPTOS_PREC_CRITIC_ECP = 0xa0,		/* The ip_tos prec critic ecp option (hopefully unused) */
		IPTOS_PREC_FLASHOVERRIDE = 0x80,	/* The ip_tos prec flashoverride option (hopefully unused) */
		IPTOS_PREC_FLASH = 0x60,			/* The ip_tos prec flash option (hopefully unused) */
		IPTOS_PREC_IMMEDIATE = 0x40,		/* The ip_tos prec immediate option (hopefully unused) */
		IPTOS_PREC_PRIORITY = 0x20,			/* The ip_tos prec priority option (hopefully unused) */
		IPTOS_PREC_ROUTINE = 0x00			/* The ip_tos prec routine option (hopefully unused) */
	};

	// Flags for ip_off.
	enum IP_
	{
		IP_DF = 0x4000,			/* Don't fragment flag */
		IP_MF = 0x2000,			/* More fragments flag */
		IP_OFFMASK = 0x1fff		/* Mask for fragmenting bits */
	};

	iphdr()
		: ip_v_hl(ip_v_hl_pack(0, 0)), ip_tos(0), ip_len(0), ip_id(0), ip_off(0),
		ip_ttl(0), ip_p(0), ip_sum(0), ip_src(struct in_addr()),
		ip_dst(struct in_addr()) { }


	// As the ip version is kept in a #ip_v_hl_pack, this function gets it from there.
	inline	const u_char ip_v() const;

	// As the ip header length is kept in a #ip_v_hl_pack,this function gets it from there.
	inline	const u_char ip_hl() const;

	// As the ip version is kept in a #ip_v_hl_pack, this function sets it.
	inline	void ip_v(const u_char& ip_v);

	// As the ip header length is kept in a #ip_v_hl_pack,this function sets it.
	inline	void ip_hl(const u_char& ip_hl);

	ip_v_hl_pack ip_v_hl;		/* Version then header length, in a ip_v_hl_pack. \note The IP header length is in 4-bytes unit */
	u_char	ip_tos;				/* Type of service \see IPTOS_ */
	u_short	ip_len;				/* Total length, including data */
	u_short	ip_id;				/* Identification */
	u_short	ip_off;				/* Fragment offset field \see IP_ */
	u_char	ip_ttl;				/* Time to live */
	u_char	ip_p;				/* Protocol */
	u_short	ip_sum;				/* Checksum */
	struct	in_addr ip_src;		/* Source and */
	struct	in_addr ip_dst;		/* Dest address */
};

struct L3::route {

	// Constructor
	route(inet_os* inet);

	// Partial constructor for ro_rt.
	void rtalloc(inet_os* inet);

	struct	L3::rtentry* ro_rt; /*!< The route entry for this route */
	struct	sockaddr ro_dst;	/*!< The route destination */
};

// Structure of the route entry (in the routing table).
struct L3::rtentry {

	// Flags for #rt_flags.
	enum RTF_
	{
		RTF_UP = 0x1,				/* Route usable */
		RTF_GATEWAY = 0x2,			/* Destination is a gateway */
		RTF_HOST = 0x4,				/* Host entry (net otherwise) */
		RTF_REJECT = 0x8,			/* Host or net unreachable */
		RTF_DYNAMIC = 0x10,			/* Created dynamically (by redirect) */
		RTF_MODIFIED = 0x20,		/* Modified dynamically (by redirect) */
		RTF_DONE = 0x40,			/* Message confirmed */
		RTF_MASK = 0x80,			/* Subnet mask present */
		RTF_CLONING = 0x100,		/* Generate new routes on use */
		RTF_XRESOLVE = 0x200,		/* External daemon resolves name */
		RTF_LLINFO = 0x400,			/* Generated by ARP or ESIS */
		RTF_STATIC = 0x800,			/* Manually added */
		RTF_BLACKHOLE = 0x1000,		/* Just discard pkts (during updates) */
		RTF_PROTO2 = 0x4000,		/* Protocol specific routing flag */
		RTF_PROTO1 = 0x8000			/* Protocol specific routing flag */
	};

	// Flags for #rtm_flags.
	enum RTM_
	{
		RTM_VERSION = 3,		/* Up the ante and ignore older versions */
		RTM_ADD = 0x1,			/* Add Route */
		RTM_DELETE = 0x2,		/* Delete Route */
		RTM_CHANGE = 0x3,		/* Change Metrics or flags */
		RTM_GET = 0x4,			/* Report Metrics */
		RTM_LOSING = 0x5,		/* Kernel Suspects Partitioning */
		RTM_REDIRECT = 0x6,		/* Told to use different route */
		RTM_MISS = 0x7,			/* Lookup failed on this address */
		RTM_LOCK = 0x8,			/* Fix specified metrics */
		RTM_OLDADD = 0x9,		/* Caused by SIOCADDRT */
		RTM_OLDDEL = 0xa,		/* Caused by SIOCDELRT */
		RTM_RESOLVE = 0xb,		/* Req to resolve dst to LL addr */
		RTM_NEWADDR = 0xc,		/* Address being added to iface */
		RTM_DELADDR = 0xd,		/* Address being removed from iface */
		RTM_IFINFO = 0xe,		/* iface going up/down etc. */
		RTM_RTTUNIT = 1000000	/* Units for rtt, rttvar, as units per sec */
	};

	// Values that represent rtvs.
	enum RTV_
	{
		RTV_MTU = 0x1,			/* Init or lock _mtu */
		RTV_HOPCOUNT = 0x2,		/* Init or lock _hopcount */
		RTV_EXPIRE = 0x4,		/* Init or lock _hopcount */
		RTV_RPIPE = 0x8,		/* Init or lock _recvpipe */
		RTV_SPIPE = 0x10,		/* Init or lock _sendpipe */
		RTV_SSTHRESH = 0x20,	/* Init or lock _ssthresh */
		RTV_RTT = 0x40,			/* Init or lock _rtt */
		RTV_RTTVAR = 0x80		/* Init or lock _rttvar */
	};

	/*
		Constructor
			* dst - The destination route.
			* report - Unused flag.
			* inet - The inet_os owning the route.
	*/
	rtentry(struct sockaddr* dst, int report, class inet_os* inet);

	// Destructor
	~rtentry();

	// Partial destructor, C-style for this object.
	void RTFREE();

	// Caster for rt_key.
	inline struct sockaddr* rt_key() const { return reinterpret_cast<struct sockaddr*>(rt_nodes->rn_key()); }

	// Caster for rt_mask.
	inline struct sockaddr* rt_mask() const { return reinterpret_cast<struct sockaddr*>(rt_nodes->rn_mask()); }

	// Gets rt_expire.
	inline u_long rt_expire() const { return rt_rmx.rmx_expire; }

	struct L3_impl::radix_node rt_nodes[2];		/* Radix search tree node layout. Tree glue, and other values */
	struct sockaddr* rt_gateway;				/* The route's gateway. */

	short				rt_flags;				/* up/down?, host/net */
	short				rt_refcnt;				/* Number of held references */
	u_long				rt_use;					/* Raw number of packets forwarded */
	inet_os* rt_ifp;							/* The answer: interface to use */
	struct	sockaddr* rt_genmask;				/* For generation of cloned routes */
	char* rt_llinfo;							/* Pointer to link level info cache */

	struct	L3_impl::rt_metrics	rt_rmx;			/* Metrics used by rx'ing protocols */
	struct	rtentry* rt_gwroute;				/* Implied entry for gatewayed routes */
};

struct L3::ip_moptions {
	inet_os* imo_multicast_ifp;		/* OS for outgoing multi casts */
	u_char	imo_multicast_ttl;		/* TTL for outgoing multi casts */
	u_char	imo_multicast_loop;		/* 1 => hear sends if a member */
	u_short	imo_num_memberships;	/* no. memberships this socket */
	struct	in_multi* imo_membership[L3_impl::IP_MAX_MEMBERSHIPS];  /* The imo membership array of size L3_impl::IP_maximum_memberships (20) */

};