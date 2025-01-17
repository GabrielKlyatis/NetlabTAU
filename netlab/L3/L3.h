#pragma once

#include "../infra/inet_os.hpp"
#include <iostream>

/********************************************************************************************/
/*										INTERFACE											*/
/********************************************************************************************/

// Represents a Layer 3 interface (IP).
class L3 : public protosw {
public:

	// Structure of an internet header, naked of options.
	struct iphdr;

	// Structure of the route entry (in the routing table).
	struct rtentry;

	// A route consists of a destination address and a reference to a routing entry.
	struct route;

	// Structure attached to inpcb::ip_moptions and passed to ip_output when IP multicast options are in use.
	struct ip_moptions;

	/*
		Constructor
			* inet - The inet_os owning this protocol.
			* pr_type - The type of the protocol.
			* pr_protocol - The protocol number.
			* pr_flags - The flags of the protocol.
	*/
	L3(class inet_os& inet, const short& pr_type = 0, const short& pr_protocol = 0, const short& pr_flags = 0)
		: protosw(inet, pr_type, nullptr, pr_protocol, pr_flags) {  }

	// pr_init - Initialize the protocol.
	virtual void pr_init() = 0;

	// pr_input - Process a received IP datagram.
	virtual int pr_output(const struct pr_output_args& args) = 0;

	// pr_output - Output IP datagram.
	virtual void pr_input(const struct pr_input_args& args) = 0;

	// Students may ignore the following functions.
private:
	virtual void pr_ctlinput() { };
	virtual int pr_ctloutput() { return 0; };
	virtual int pr_usrreq(class netlab::L5_socket* so, int req, std::shared_ptr<std::vector<byte>>m,
		struct sockaddr* nam, size_t nam_len, std::shared_ptr<std::vector<byte>> control) {
		return 0;
	}
	virtual void pr_fasttimo() { };
	virtual void pr_slowtimo() { };
	virtual void pr_drain() { };
	virtual int pr_sysctl() { return 0; };
};