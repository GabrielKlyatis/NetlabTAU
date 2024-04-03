#pragma once

#include "tcp_tahoe.h"

class tcp_reno : public tcp_tahoe
{

	tcp_reno() = default;
	~tcp_reno() = default;

protected:

	void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) override;

	void tcp_rto_timer_handler(tcpcb* tp) override;

};



