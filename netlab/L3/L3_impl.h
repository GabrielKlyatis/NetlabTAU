#pragma once

#include "L3.h"

class L3_impl : public L3
{
public:

	L3_impl(class inet_os& inet, const short& pr_type = 0, const short& pr_protocol = 0, const short& pr_flags = 0);

	virtual void pr_init();
	virtual void pr_input(const struct pr_input_args& args);
	virtual int pr_output(const struct pr_output_args& args);

	/************************************************************************/
	/*                         ip_output_args                               */
	/************************************************************************/

	struct ip_output_args : public pr_output_args
	{
		ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it,
			std::shared_ptr<std::vector<byte>>& opt, struct L3::route* ro, int flags, struct  L3::ip_moptions* imo)
			: m(m), it(it), opt(opt), ro(ro), flags(flags), imo(imo) { }

		std::shared_ptr<std::vector<byte>>& m;		/*!< The std::shared_ptr<std::vector<byte>> to process. */
		std::vector<byte>::iterator& it;			/*!< The iterator, maintaining the current offset in the vector. */
		std::shared_ptr<std::vector<byte>>& opt;	/*!< The IP option \warning Must be std::shared_ptr<std::vector<byte>>(nullptr) as options are not supported. */
		struct L3::route* ro;						/*!< The route for the packet. Should only use the ro_dst member to hold the sockaddr for the output route. */
		int flags;									/*!< The flags \see IP_OUTPUT_. */
		struct  L3::ip_moptions* imo;				/*!< The IP multicast options \warning Must be nullptr as multicast are not supported. */
	};

private:

	void ip_init();
	inline int ip_output(const struct ip_output_args& args);
};