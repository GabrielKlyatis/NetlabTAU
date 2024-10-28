#include "L4.h"

#include "../Sniffer/tins.h"

#include "../L3/L3.h"
#include "../L1/NIC.h"
#include "../infra/Print.h"
#include <bitset>

/* Collapse namespaces */
using namespace std;
using namespace Tins;
using namespace netlab;

L4::L4(bool debug, class inet_os& inet) : debug(debug), inet(inet), recvPacketLen(0), recvPacket(NULL)
{
	pthread_mutex_init(&recvPacket_mutex, NULL);
	pthread_mutex_lock(&recvPacket_mutex);
}

L3* L4::getNetworkLayer() { return reinterpret_cast<L3*>(inet.inetsw(protosw::SWPROTO_IP_RAW)); }

int L4::sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP)
{
	IP::address_type resolvedSrcIP;
	try 
	{
		resolvedSrcIP = IP::address_type(srcIP);
	}
	catch (std::runtime_error &ex) 
	{
		if (srcIP != "")
		{
			//pthread_mutex_lock(&NIC::print_mutex);
			cout << "[@] Source IP resolving failed with the error: " << ex.what() << endl;
			cout << "    Using myIP as a Source IP." << endl;
			//pthread_mutex_unlock(&NIC::print_mutex);
		}
		try {
			resolvedSrcIP = IP::address_type(inet.nic()->ip_addr().s_addr);
		}
		catch (std::runtime_error &ex) 
		{
			//pthread_mutex_lock(&NIC::print_mutex);
			cout << "[!] Source IP resolving failed AGAIN with the error: " << ex.what() << endl;
			//pthread_mutex_unlock(&NIC::print_mutex);
		}	
	}

	IP::address_type resolvedDestIP;
	try 
	{
		resolvedDestIP = IP::address_type(destIP);
	}
	catch (std::runtime_error &ex) 
	{
		//pthread_mutex_lock(&NIC::print_mutex);
		cout << "[!] Destination IP resolving failed with the error: " << ex.what() << endl;
		//pthread_mutex_unlock(&NIC::print_mutex);
		resolvedDestIP = "";
	}

	/* Create an ICMP header */
	ICMP icmp_pdu;
	icmp_pdu.id(RNG16());
	icmp_pdu.code(0);
	RawPDU raw_pdu(sendData, sendDataLen);
	icmp_pdu.inner_pdu(raw_pdu);

	std::shared_ptr<std::vector<byte>> toSend = std::make_unique<std::vector<byte>>(icmp_pdu.size());
	RawData(icmp_pdu, toSend);
	
	//int ret = getNetworkLayer->sendToL3(toSend, icmp_pdu.size(), resolvedSrcIP.to_string(), resolvedDestIP.to_string());

	int ret = 0;

	return ret;
}

int L4::readFromL4(byte *recvData, size_t recvDataLen)
{
	pthread_mutex_lock(&recvPacket_mutex);
	size_t lSize = recvDataLen < recvPacketLen ? recvDataLen : recvPacketLen;
	memcpy(recvData, recvPacket, lSize);
	pthread_mutex_unlock(&recvPacket_mutex);
	pthread_mutex_lock(&recvPacket_mutex);
	return lSize;
}


int L4::recvFromL4(byte *recvData, size_t recvDataLen)
{
	ICMP icmp_pdu(recvData, recvDataLen);
	int ret = 0;
	if (icmp_pdu.code() == 0 && icmp_pdu.type() == ICMP::ECHO_REPLY)
	{
		if (debug)
		{
			//pthread_mutex_lock(&NIC::print_mutex);
			cout << "[#] ICMP packet receivied!" << endl;
			//printPDU(icmp_pdu);
			//pthread_mutex_unlock(&NIC::print_mutex);
		}
		RawPDU raw_pdu(icmp_pdu.rfind_pdu<RawPDU>());
		recvPacketLen = raw_pdu.size();
		ret = recvPacketLen;
		if (recvPacket)
			delete[] recvPacket;
		recvPacket = new byte[recvPacketLen];
		RawData(raw_pdu, recvPacket, recvPacketLen);
		//pthread_mutex_unlock(&recvPacket_mutex);	
	}
	else
	{
		//pthread_mutex_lock(&NIC::print_mutex);
		cout << "[!] ICMP type not supported, only ECHO_REPLY is currently supported, Droping Packet." << endl;
		//pthread_mutex_unlock(&NIC::print_mutex);
		return ret;
	}
	return ret;
}

L4::~L4()
{
	pthread_mutex_destroy(&recvPacket_mutex);	/* Free up the_mutex */
	if (recvPacket)
		delete[] recvPacket;
}

