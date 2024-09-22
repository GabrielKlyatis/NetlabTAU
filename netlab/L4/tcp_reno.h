#pragma once

#include "tcp_tahoe.h"

class tcp_reno : public tcp_tahoe
{

public:

	tcp_reno(class inet_os& inet);
	~tcp_reno() = default;

protected:

	void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) override;

	void tcp_congestion_conrol_handler(tcpcb* tp) override;

};



