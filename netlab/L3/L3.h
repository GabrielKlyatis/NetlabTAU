/*!
    \file	L3.h
    
	\author	Tom Mahler, contact at tommahler@gmail.com
	
    \brief	Declares the L3 class.
*/
#pragma once

/*!
	\def	NETLAB_L3_DEBUG
	Define in order to printout the L3 packets for debug
*/
//#define NETLAB_L3_DEBUG

#include "../infra/inet_os.hpp"
#include <iostream>

/*!
    \class	L3

    \brief
    Represents a Layer 3 interface (IP).
    
    \pre	First initialize an instance of inet_os.
    \pre	Must define struct L3::iphdr.
    \pre	Must define struct L3::rtentry.
    \pre	Must define struct L3::route.
    \pre	Must define struct L3::ip_moptions.
    \note
    Though we do not support routing, forwarding nor multi-casting,
    we must define these structs for the sake of consistency.

    \sa	protosw
*/
class L3 
	: public protosw {
public:

	/*!
	    \struct	iphdr
	
	    \brief
	    Structure of an internet header, naked of options.
	    
	    \note Defined for the sake of consistency.
	*/
	struct iphdr;

	/*!
	    \struct	rtentry
	
	    \brief
	    Structure of the route entry (in the routing table).
	    
	    We distinguish between routes to hosts and routes to networks, preferring the former if
	    available. For each route we infer the interface to use from the gateway address supplied
	    when the route was entered. Routes that forward packets through gateways are marked so
	    that the output routines know to address the gateway rather than the ultimate destination.
	    
	    \note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rtentry;

	/*!
	    \struct	route
	
	    \brief
	    Structure of a route.
	    
	    A route consists of a destination address and a reference to a routing entry. These are
	    often held by protocols in their control blocks, e.g. \ref inpcb.
	    
		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct route;

	/*!  \relates inpcb
	\struct	ip_moptions

	\brief
	Structure attached to inpcb::ip_moptions and passed to ip_output when IP multicast
	options are in use.

	\note This struct is defined for both consistencies and support multi casting in the future.
	*/
	struct ip_moptions;

	/*!
	    \fn
	    L3::L3(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	    \param	pr_type			Type of the pr.
	    \param	pr_protocol 	The pr protocol.
	    \param	pr_flags		The pr flags.
	*/
	L3(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0) 
		: protosw(inet, pr_type, nullptr, pr_protocol, pr_flags) {  }

	virtual void pr_init() = 0;
	virtual int pr_output(const struct pr_output_args &args) = 0;
	virtual void pr_input(const struct pr_input_args &args) = 0;

	/*!
	\struct	ip_output_args

	\brief	Arguments for IP output.

	\sa	pr_output_args
	*/
	struct ip_output_args : public pr_output_args
	{
		ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it, std::shared_ptr<std::vector<byte>>& opt, struct L3::route* ro, int flags, struct  L3::ip_moptions* imo);

		std::shared_ptr<std::vector<byte>>& m;		/*!< The std::shared_ptr<std::vector<byte>> to process. */
		std::vector<byte>::iterator& it;			/*!< The iterator, maintaining the current offset in the vector. */
		std::shared_ptr<std::vector<byte>>& opt;	/*!< The IP option \warning Must be std::shared_ptr<std::vector<byte>>(nullptr) as options are not supported. */
		struct L3::route* ro;						/*!< The route for the packet. Should only use the ro_dst member to hold the sockaddr for the output route. */
		int flags;									/*!< The flags \see IP_OUTPUT_. */
		struct  L3::ip_moptions* imo;				/*!< The IP multicast options \warning Must be nullptr as multicast are not supported. */
	};

	/*!
		\typedef	u_short n_short

		\brief	Defines an alias representing the short as received from the net.
	*/
	typedef u_short n_short;

	/*!
		\typedef	u_long n_long

		\brief	Defines an alias representing the long as received from the net.
	*/
	typedef u_long	n_long;

	/*!
		\typedef	u_long n_time

		\brief	Defines an alias representing the time in ms since 00:00 GMT, byte rev.
	*/
	typedef	u_long	n_time;

	enum ip_things // please rename 
	{
		IPVERSION = 4,					/*!< Definitions for internet protocol version 4. \sa Per RFC 791, September 1981 */
		MAX_IPOPTLEN = 40,				/*!< The actual length of the options (including ipopt_dst). */
		IP_MAX_MEMBERSHIPS = 20,		/*!< per socket; must fit in one mbuf (legacy) */
		IP_MAXPACKET = 65535,			/*!< The maximum packet size */
		IP_MSS = 576,					/*!< The default maximum segment size */
		IP_DEFAULT_MULTICAST_TTL = 1	/*!< normally limit multi casts to 1 hop */
	};

	/*!
		\enum	IPOPT_

		\brief	Definitions for options.
	*/
	enum IPOPT_
	{
		IPOPT_EOL = 0,			/*!< end of option list */
		IPOPT_NOP = 1,			/*!< no operation */
		IPOPT_RR = 7,			/*!< record packet route */
		IPOPT_TS = 68,			/*!< timestamp */
		IPOPT_SECURITY = 130,	/*!< provide s,c,h,tcc */
		IPOPT_LSRR = 131,		/*!< loose source route */
		IPOPT_SATID = 136,		/*!< satnet id */
		IPOPT_SSRR = 137,		/*!< strict source route */

		/*
		* Offsets to fields in options other than EOL and NOP.
		*/
		IPOPT_OPTVAL = 0,		/*!< option ID */
		IPOPT_OLEN = 1,			/*!< option length */
		IPOPT_OFFSET = 2,		/*!< offset within option */
		IPOPT_MINOFF = 4		/*!< min value of above */
	};

	/*!
		\enum	IPOPT_SECUR_

		\brief	Security Options for Internet Protocol (IPSO) as defined in RFC 1108.

		\see RFC 1108
	*/
	enum IPOPT_SECUR_
	{
		IPOPT_SECUR_UNCLASS = 0x0000,   /*!< The Security Options for Unclassified option */
		IPOPT_SECUR_CONFID = 0xf135,	/*!< The Security Options for Confidential option */
		IPOPT_SECUR_EFTO = 0x789a,		/*!< The Security Options for EFTO option */
		IPOPT_SECUR_MMMM = 0xbc4d,		/*!< The Security Options for MMMM option */
		IPOPT_SECUR_RESTR = 0xaf13,		/*!< The The Security Options for RESTR option */
		IPOPT_SECUR_SECRET = 0xd788,	/*!< The The Security Options for Secret option */
		IPOPT_SECUR_TOPSECRET = 0x6bc5  /*!< The The Security Options for Top Secret option */
	};

	/*!
		\enum	TTL_

		\brief	Internet implementation parameters for Time-To-Live.
	*/
	enum TTL_
	{
		MAXTTL = 255,		/*!< maximum time to live (seconds) */
		IPDEFTTL = 64,		/*!< default ttl, from RFC 1340 */
		IPFRAGTTL = 60,		/*!< time to live for frags, slowhz */
		IPTTLDEC = 1		/*!< subtracted when forwarding */
	};

	/*!
		\enum	IP_OUTPUT_

		\brief	Flags passed to ip_output as last parameter.
	*/
	enum IP_OUTPUT_
	{
		IP_FORWARDING = 0x1,				/*!< most of ip header exists */
		IP_RAWOUTPUT = 0x2,					/*!< raw ip header exists */
		IP_ROUTETOIF = SO_DONTROUTE,		/*!< bypass routing tables */
		IP_ALLOWBROADCAST = SO_BROADCAST	/*!< can send broadcast packets */
	};

	/*!
		\struct	rt_metrics

		\brief
		These numbers are used by reliable protocols for determining retransmission behavior and
		are included in the routing structure.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_metrics {

		/*!
			\fn	rt_metrics();

			\brief	Default constructor.
		*/

		rt_metrics();

		u_long	rmx_locks;		/*!< Kernel must leave these values alone */
		u_long	rmx_mtu;		/*!< /* MTU for this path */
		u_long	rmx_hopcount;   /*!< Max hops expected */
		u_long	rmx_expire;		/*!< Lifetime for route, e.g. redirect */
		u_long	rmx_recvpipe;   /*!< Inbound delay-bandwith product */
		u_long	rmx_sendpipe;   /*!< Outbound delay-bandwith product */
		u_long	rmx_ssthresh;   /*!< Outbound gateway buffer limit */
		u_long	rmx_rtt;		/*!< Estimated round trip time */
		u_long	rmx_rttvar;		/*!< Estimated rtt variance */
		u_long	rmx_pksent;		/*!< Packets sent using this route */
	};

	/*!
		\struct	rt_addrinfo

		\brief
		A route addrinfo.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_addrinfo {

		/*!
			\enum	RTAX_

			\brief	Index offsets for sockaddr array for alternate internal encoding.
		*/
		enum RTAX_
		{
			RTAX_DST = 0,		/*!< destination sockaddr present */
			RTAX_GATEWAY = 1,	/*!< gateway sockaddr present */
			RTAX_NETMASK = 2,	/*!< netmask sockaddr present */
			RTAX_GENMASK = 3,	/*!< cloning mask sockaddr present */
			RTAX_IFP = 4,		/*!< interface name sockaddr present */
			RTAX_IFA = 5,		/*!< interface addr sockaddr present */
			RTAX_AUTHOR = 6,	/*!< sockaddr for author of redirect */
			RTAX_BRD = 7,		/*!< for NEWADDR, broadcast or p-p dest addr */
			RTAX_MAX = 8		/*!< size of array to allocate */
		};

		int	rti_addrs;							/*!< The rti addrs */
		struct sockaddr* rti_info[RTAX_MAX];	/*!< The rti info[rtax max] array */
	};

	/*!
		\struct	rt_msghdr

		\brief
		Structures for routing messages.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_msghdr {

		/*!
			\typedef	int32_t pid_t

			\brief	Defines an alias representing the process id.
		*/
		typedef	int32_t	pid_t;

		u_short	rtm_msglen;			/*!< to skip over non-understood messages */
		u_char	rtm_version;		/*!< future binary compatibility */
		u_char	rtm_type;			/*!< message type */
		u_short	rtm_index;			/*!< index for associated ifp */
		int	rtm_flags;				/*!< flags, including kern & message, e.g. DONE */
		int	rtm_addrs;				/*!< bitmask identifying sockaddrs in msg */
		pid_t	rtm_pid;			/*!< identify sender */
		int	rtm_seq;				/*!< for sender to identify action */
		int	rtm_errno;				/*!< why failed */
		int	rtm_use;				/*!< from rtentry */
		u_long	rtm_inits;			/*!< which metrics we are initializing */
		struct	rt_metrics rtm_rmx; /*!< metrics themselves */
	};

	/*!
		\struct	radix_mask

		\brief
		Annotations to tree concerning potential routes applying to subtrees.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct radix_mask {

		/*!
			\fn	inline char* rm_mask() const

			\brief	Gets the rm_mask.

			\return	rm_rmu.rmu_mask.
		*/
		inline char* rm_mask() const { return rm_rmu.rmu_mask; }

		/*!
			\fn	inline radix_node* rm_leaf() const

			\brief	Gets rm_leaf.

			\return
			rm_rmu.rmu_leaf.

			\note extra field would make 32 bytes.
		*/
		inline struct radix_node* rm_leaf() const { return rm_rmu.rmu_leaf; }

		short	rm_b;					/*!< bit offset; -1-index(netmask) */
		char	rm_unused;				/*!< cf. rn_bmask */
		u_char	rm_flags;				/*!< cf. rn_flags */
		struct	radix_mask* rm_mklist;	/*!< more masks to try */

		union {
			char* rmu_mask;				/*!< the mask */
			struct	radix_node* rmu_leaf;	/*!< for normal routes */
		}	rm_rmu;

		int	rm_refs;						/*!< # of references to this struct */
	};

	/*!
		\struct	radix_node

		\brief	Radix search tree node layout.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct radix_node {

		/*!
			\enum	RNF_

			\brief	Flags for #rn_flags.
		*/
		enum RNF_
		{
			RNF_NORMAL = 1,	/*!< leaf contains normal route */
			RNF_ROOT = 2,	/*!< leaf is root leaf for tree */
			RNF_ACTIVE = 4	/*!< This node is alive (for rtfree) */
		};

		/*!
			\fn	radix_node();

			\brief	Default constructor.
		*/
		radix_node();

		/*!
			\fn	inline radix_node* rn_dupedkey() const

			\brief	Gets rn_dupedkey.

			\return	rn_u.rn_leaf.rn_Dupedkey.
		*/
		inline struct radix_node* rn_dupedkey() const { return rn_u.rn_leaf.rn_Dupedkey; }

		/*!
			\fn	inline char* rn_key() const

			\brief	Gets rn_key.

			\return	rn_u.rn_leaf.rn_Key.
		*/
		inline char* rn_key() const { return rn_u.rn_leaf.rn_Key; }

		/*!
			\fn	inline char* rn_mask() const

			\brief	Gets rn_mask.

			\return	rn_u.rn_leaf.rn_Mask.
		*/
		inline char* rn_mask() const { return rn_u.rn_leaf.rn_Mask; }

		/*!
			\fn	inline int& rn_off()

			\brief	Gets rn_off.

			\return	rn_u.rn_node.rn_Off;
		*/
		inline int& rn_off() { return rn_u.rn_node.rn_Off; }

		/*!
			\fn	inline radix_node* rn_l() const

			\brief	Gets rn_l.

			\return	rn_u.rn_node.rn_L.
		*/
		inline struct radix_node* rn_l() const { return rn_u.rn_node.rn_L; }

		/*!
			\fn	inline radix_node* rn_r() const

			\brief	Gets rn_r.

			\return	rn_u.rn_node.rn_R.
		*/
		inline struct radix_node* rn_r() const { return rn_u.rn_node.rn_R; }

		struct	radix_mask* rn_mklist;	/*!< list of masks contained in subtree */
		struct	radix_node* rn_p;		/*!< parent */

		short	rn_b;					/*!< bit offset; -1-index(netmask) */
		char	rn_bmask;				/*!< node: mask for bit test*/
		u_char	rn_flags;				/*!< enumerated above */

		union {
			struct {								/*!< leaf only data: */
				char* rn_Key;					/*!< object of search */
				char* rn_Mask;					/*!< netmask, if present */
				struct	radix_node* rn_Dupedkey;	/*!< The rn dupedkey */
			} rn_leaf;
			struct {						/*!< node only data: */
				int	rn_Off;					/*!< where to start compare */
				struct	radix_node* rn_L;	/*!< progeny */
				struct	radix_node* rn_R;	/*!< progeny */
			} rn_node;
		}		rn_u;
	};

private:
	virtual void pr_ctlinput() { };
	virtual int pr_ctloutput() { return 0; };	
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>>m,
		struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> control) {	return 0; }
	virtual void pr_fasttimo() { };	
	virtual void pr_slowtimo() { };	
	virtual void pr_drain() { };		
	virtual int pr_sysctl() { return 0; };		
};

/************************************************************************/
/*                         ip_output_args                               */
/************************************************************************/

L3::ip_output_args::ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it,
	std::shared_ptr<std::vector<byte>>& opt, struct L3::route* ro, int flags, struct  L3::ip_moptions* imo)
	: m(m), it(it), opt(opt), ro(ro), flags(flags), imo(imo) { }



struct L3::iphdr {

	/*!
	    \typedef	struct u_char_pack ip_v_hl_pack
	
	    \brief
	    Defines an alias representing the two 4-bit pack of version and header length, according
	    to windows byte order (BIG_ENDIAN).
	*/
	typedef struct u_char_pack ip_v_hl_pack;

	iphdr() 
		: ip_v_hl(ip_v_hl_pack(0, 0)), ip_tos(0), ip_len(0), ip_id(0), ip_off(0),
		ip_ttl(0), ip_p(0), ip_sum(0), ip_src(struct in_addr()),
		ip_dst(struct in_addr()) { }


	ip_v_hl_pack ip_v_hl;		/*!< version then header length, in a ip_v_hl_pack. \note The IP header length is in 4-bytes unit */
	u_char	ip_tos;				/*!< type of service \see IPTOS_ */
	u_short	ip_len;				/*!< total length, including data */
	u_short	ip_id;				/*!< identification */
	u_short	ip_off;				/*!< fragment offset field \see IP_ */
	u_char	ip_ttl;				/*!< time to live */
	u_char	ip_p;				/*!< protocol */
	u_short	ip_sum;				/*!< checksum */
	struct	in_addr ip_src;		/*!< source and */
	struct	in_addr ip_dst;		/*!< dest address */
};

/*!
    \struct	L3::route

    \brief
    Structure of a route.
    
    A route consists of a destination address and a reference to a routing entry. These are often
    held by protocols in their control blocks, e.g. \ref inpcb.
    
    \note This struct is defined for both consistencies and support routing in the future.
*/
struct L3::route {

	/*!
	    \fn	route(inet_os *inet);
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	If non-null, the inet.
	*/
	route(inet_os *inet);

	/*!
	    \fn	void rtalloc(inet_os *inet);
	
	    \brief	Partial constructor for #ro_rt.
	
	    \param [in,out]	inet	for #ro_rt.
	*/
	void rtalloc(inet_os *inet);

	struct	L3::rtentry *ro_rt; /*!< The route entry for this route */
	struct	sockaddr ro_dst;	/*!< The route destination */
};

/*!
    \struct	L3::rtentry

    \brief
    Structure of the route entry (in the routing table).
    
    We distinguish between routes to hosts and routes to networks, preferring the former if
    available. For each route we infer the interface to use from the gateway address supplied
    when the route was entered. Routes that forward packets through gateways are marked so that
    the output routines know to address the gateway rather than the ultimate destination.
    
    \note This struct is defined for both consistencies and support routing in the future.
*/
struct L3::rtentry {

	/*!
	    \enum	RTF_
	
	    \brief	Flags for #rt_flags.
	*/
	enum RTF_ 
	{
		RTF_UP = 0x1,				/*!< route usable */
		RTF_GATEWAY = 0x2,			/*!< destination is a gateway */
		RTF_HOST = 0x4,				/*!< host entry (net otherwise) */
		RTF_REJECT = 0x8,			/*!< host or net unreachable */
		RTF_DYNAMIC = 0x10,			/*!< created dynamically (by redirect) */
		RTF_MODIFIED = 0x20,		/*!< modified dynamically (by redirect) */
		RTF_DONE = 0x40,			/*!< message confirmed */
		RTF_MASK = 0x80,			/*!< subnet mask present */
		RTF_CLONING = 0x100,		/*!< generate new routes on use */
		RTF_XRESOLVE = 0x200,		/*!< external daemon resolves name */
		RTF_LLINFO = 0x400,			/*!< generated by ARP or ESIS */
		RTF_STATIC = 0x800,			/*!< manually added */
		RTF_BLACKHOLE = 0x1000,		/*!< just discard pkts (during updates) */
		RTF_PROTO2 = 0x4000,		/*!< protocol specific routing flag */
		RTF_PROTO1 = 0x8000			/*!< protocol specific routing flag */
	};

	/*!
	    \enum	RTM_
	
	    \brief	Flags for #rtm_flags.
	*/
	enum RTM_ 
	{
		RTM_VERSION = 3,		/*!< Up the ante and ignore older versions */
		RTM_ADD = 0x1,			/*!< Add Route */
		RTM_DELETE = 0x2,		/*!< Delete Route */
		RTM_CHANGE = 0x3,		/*!< Change Metrics or flags */
		RTM_GET = 0x4,			/*!< Report Metrics */
		RTM_LOSING = 0x5,		/*!< Kernel Suspects Partitioning */
		RTM_REDIRECT = 0x6,		/*!< Told to use different route */
		RTM_MISS = 0x7,			/*!< Lookup failed on this address */
		RTM_LOCK = 0x8,			/*!< fix specified metrics */
		RTM_OLDADD = 0x9,		/*!< caused by SIOCADDRT */
		RTM_OLDDEL = 0xa,		/*!< caused by SIOCDELRT */
		RTM_RESOLVE = 0xb,		/*!< req to resolve dst to LL addr */
		RTM_NEWADDR = 0xc,		/*!< address being added to iface */
		RTM_DELADDR = 0xd,		/*!< address being removed from iface */
		RTM_IFINFO = 0xe,		/*!< iface going up/down etc. */
		RTM_RTTUNIT = 1000000	/*!< units for rtt, rttvar, as units per sec */
	};

	/*!
	    \enum	RTV_
	
	    \brief	Values that represent rtvs.
	*/
	enum RTV_ 
	{
		RTV_MTU = 0x1,			/*!< init or lock _mtu */
		RTV_HOPCOUNT = 0x2,		/*!< init or lock _hopcount */
		RTV_EXPIRE = 0x4,		/*!< init or lock _hopcount */
		RTV_RPIPE = 0x8,		/*!< init or lock _recvpipe */
		RTV_SPIPE = 0x10,		/*!< init or lock _sendpipe */
		RTV_SSTHRESH = 0x20,	/*!< init or lock _ssthresh */
		RTV_RTT = 0x40,			/*!< init or lock _rtt */
		RTV_RTTVAR = 0x80		/*!< init or lock _rttvar */
	};



	/*!
	    \fn	rtentry(struct sockaddr *dst, int report, class inet_os *inet);
	
	    \brief	Constructor.
	
	    \param [in,out]	dst 	If non-null, the destination route.
	    \param	report			Unused flag.
	    \param [in,out]	inet	The inet_os owning the route.
	*/
	rtentry(struct sockaddr *dst, int report, class inet_os *inet);

	/*!
	    \fn	~rtentry();
	
	    \brief	Destructor.
	*/
	~rtentry();

	/*!
	    \fn	void RTFREE();
	
	    \brief	Partial destructor, C-style for this object.
	*/
	void RTFREE();

	/*!
	    \fn	inline sockaddr* rt_key() const
	
	    \brief	Caster for rt_key.
	
	    \return	sockaddr* cast of rt_nodes->rn_key() using reinterpret_cast.
	*/
	//inline struct sockaddr* rt_key() const { return reinterpret_cast<struct sockaddr *>(rt_nodes->rn_key()); }

	/*!
	    \fn	inline sockaddr* rt_mask() const
	
	    \brief	Caster for rt_mask.
	
	    \return	sockaddr* cast of rt_nodes->rn_mask() using reinterpret_cast.
	*/
	//inline struct sockaddr* rt_mask() const { return reinterpret_cast<struct sockaddr *>(rt_nodes->rn_mask()); }

	/*!
	    \fn	inline u_long rt_expire() const
	
	    \brief	Gets rt_expire.
	
	    \return	rt_rmx.rmx_expire.
	*/
	//inline u_long rt_expire() const { return rt_rmx.rmx_expire; }

	struct sockaddr *rt_gateway;				/*!< The route's gateway. */

	short				rt_flags;		/*!< up/down?, host/net */
	short				rt_refcnt;		/*!< # held references */
	u_long				rt_use;			/*!< raw # packets forwarded */
	inet_os				*rt_ifp;		/*!< the answer: interface to use */
	struct	sockaddr	*rt_genmask;	/*!< for generation of cloned routes */
	char				*rt_llinfo;		/*!< pointer to link level info cache */

	/*!
		\note	These numbers are used by reliable protocols for determining retransmission
		behavior and are included in the routing structure.
	*/
	struct	rtentry		*rt_gwroute;		/*!< implied entry for gatewayed routes */
};
