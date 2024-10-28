/*!
    \file	L3_impl.cpp

	\author	Tom Mahler, contact at tommahler@gmail.com

    \brief	Implements the L3 class.
*/

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include "L3_impl.h"

#include <iomanip>
#include <algorithm>
#include "../L2/L2.h"
#include "../L1/NIC.h"

/************************************************************************/
/*                         L3_impl				                        */
/************************************************************************/

L3_impl::L3_impl(class inet_os &inet, const short &pr_type, const short &pr_protocol, const short &pr_flags)
	: L3(inet, pr_type, pr_protocol, pr_flags) { }

void L3_impl::pr_init() {
	// INSERT IMPLEMENTATION HERE
}

int L3_impl::pr_output(const struct pr_output_args &args) {
	// INSERT IMPLEMENTATION HERE
	return 0;
};		


void L3_impl::pr_input(const struct pr_input_args &args) {
	// INSERT IMPLEMENTATION HERE
}


void L3_impl::ip_init() {
	
}

int L3_impl::ip_output(const struct ip_output_args &args) {
	return 0;
}
