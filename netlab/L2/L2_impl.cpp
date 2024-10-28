#include "L2.h"

#include <iomanip>
#include <string>

#include "L2_ARP.h"
#include "../L3/L3.h"
#include "../L1/NIC.h"
#include "../infra/HWAddress.hpp"

/************************************************************************/
/*                         L2			                                */
/************************************************************************/

L2::L2(class inet_os &inet) : inet(inet) { inet.datalink(this); }

L2::~L2() { inet.datalink(nullptr); }

/************************************************************************/
/*                         L2_impl		                                */
/************************************************************************/


L2_impl::L2_impl(class inet_os &inet) : L2(inet) { }

void L2_impl::ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) {
	// INSERT IMPLEMENTATION HERE
}

void L2_impl::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt0) 
{
	// INSERT IMPLEMENTATION HERE
}