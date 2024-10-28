#pragma once

#include "L3.h"

class L3_impl : public L3
{
public:

	L3_impl(class inet_os& inet, const short& pr_type = 0, const short& pr_protocol = 0, const short& pr_flags = 0);

	virtual void pr_init();
	virtual void pr_input(const struct pr_input_args& args);
	virtual int pr_output(const struct pr_output_args& args);

private:

	void ip_init();
	inline int ip_output(const struct ip_output_args& args);
};