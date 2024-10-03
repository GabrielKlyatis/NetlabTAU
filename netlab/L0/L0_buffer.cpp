#include "L0_buffer.h"

#include "../infra/inet_os.hpp"
#include "../L1/NIC_Cable.h"



L0_buffer::L0_buffer(class inet_os &inet, double reliability, distribution dist_delay, DIRECTION d, BUFF_TYPE type)
	: cable(*inet.cable()), uniform_real_reli(std::uniform_real_distribution<>()), dist_delay(dist_delay),
	reliability((reliability >= 0 && reliability <= 1) ? reliability : 0.5), d(d), buff_type(type)
{
	cable.buf = this;
}

L0_buffer::L0_buffer(class inet_os &inet, double reliability, DIRECTION d, BUFF_TYPE type) : L0_buffer(inet, reliability, no_dist, d, type) { }


L0_buffer::L0_buffer(class inet_os &inet, double reliability, const exponential_distribution_args &args, DIRECTION d, BUFF_TYPE type)
	: L0_buffer(inet, reliability, exponential_distribution, d, type)
{
	this->exp_delay = std::exponential_distribution<>(args.lambda);
}

L0_buffer::L0_buffer(class inet_os &inet, double reliability, const uniform_real_distribution_args &args, DIRECTION d, BUFF_TYPE type)
	: L0_buffer(inet, reliability, uniform_real_distribution, d, type)
{
	this->uniform_real_delay = std::uniform_real_distribution<>(args.a, args.b);
}

L0_buffer::L0_buffer(class inet_os &inet, double reliability, const chi_squared_distribution_args &args, DIRECTION d, BUFF_TYPE type)
	: L0_buffer(inet, reliability, chi_squared_distribution, d, type)
{
	this->chi_squared_delay = std::chi_squared_distribution<>(args.n);
}

L0_buffer::L0_buffer(class inet_os &inet, double reliability, const constant_args &args, DIRECTION d, BUFF_TYPE type)
	: L0_buffer(inet, reliability, constant, d, type)
{
	this->const_delay = args.c;
}

L0_buffer::~L0_buffer()
{
	cable.buf = nullptr;
}

void L0_buffer::send_l2_helper(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface)
{
	if (d == OUTGOING || d == BOTH) {
		if (buff_type == DROP_DELAY)
			process_drop_delay();

		else if (reliability < uniform_real_reli(gen)) { // we dont care performance here, so maybe add tiny delay
			//std::cout << "output DUP DUP DUP" << std::endl;
			cable.send_l2_helper(m, it, iface);
			std::this_thread::sleep_for(std::chrono::microseconds(30));
			cable.send_l2_helper(m, it, iface);
			std::this_thread::sleep_for(std::chrono::microseconds(30));
			cable.send_l2_helper(m, it, iface);
			std::this_thread::sleep_for(std::chrono::microseconds(30));
			cable.send_l2_helper(m, it, iface);
			std::this_thread::sleep_for(std::chrono::microseconds(30));
		}
			
	}
		
	cable.send_l2_helper(m, it, iface);
}

void L0_buffer::leread(class std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it) 
{	
	if (d == INCOMING || d == BOTH) {
		if (buff_type == DROP_DELAY)
			process_drop_delay();
		else if (reliability < uniform_real_reli(gen)) { // we dont care performance here, so maybe add tiny delay
			//std::cout << "input DUP DUP DUP" << std::endl;
			cable.inet.nic()->leread(m, it);
			std::this_thread::sleep_for(std::chrono::microseconds(15));
			cable.inet.nic()->leread(m, it);
			std::this_thread::sleep_for(std::chrono::microseconds(15));
			cable.inet.nic()->leread(m, it);
			std::this_thread::sleep_for(std::chrono::microseconds(15));
		}
	}
	cable.inet.nic()->leread(m, it); 
}
// process this 
void L0_buffer::process_drop_delay() {
	if (reliability < uniform_real_reli(gen))
	{
#define NETLAB_L0_DROP_DEBUG
#ifdef NETLAB_L0_DROP_DEBUG
		std::lock_guard<std::mutex> lock(cable.inet.print_mutex);
		std::cout << "[#] Packet was dropped!" << std::endl;
#endif
		return;
	}

	seconds delay;
	switch (dist_delay)
	{
	case L0_buffer::exponential_distribution:
		delay = seconds(exp_delay(gen));
		break;
	case L0_buffer::chi_squared_distribution:
		delay = seconds(chi_squared_delay(gen));
		break;
	case L0_buffer::uniform_real_distribution:
		delay = seconds(uniform_real_delay(gen));
		break;
	case L0_buffer::constant:
		delay = seconds(const_delay);
		break;
	case L0_buffer::no_dist:
		return;
		break;
	}
#define NETLAB_L0_DELAY_DEBUG
#ifdef NETLAB_L0_DELAY_DEBUG
	{
		std::lock_guard<std::mutex> lock(cable.inet.print_mutex);
		std::cout << "[#] Packet is delayed for: " << delay.count() << " seconds." << std::endl;
	}
#endif
	std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(delay));
}

