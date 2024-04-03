
#pragma once

#include "L4_TCP.h"

/*!
    \class	tcp_tahoe

    \brief	A tcp_tahoe implementation - implementing congetion avoidance and fast retransmit.

    \sa	L4_TCP
*/
class tcp_tahoe : public L4_TCP_impl
{
 public:

	tcp_tahoe(class inet_os& inet);
	~tcp_tahoe() = default; // automaticlly call father d'tor

protected:

    void tcp_dupacks_handler(tcpcb* tp, tcp_seq& seq) override;

    void tcp_congestion_conrol_handler(tcpcb* tp) override;

    void tcp_rto_timer_handler(tcpcb* tp) override;

};

