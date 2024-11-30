#include <WinSock2.h>
#include <iostream>

#include "L5/L5.h"
#include "L4/L4_TCP_impl.h"
#include "L3/L3.h"
#include "L2/L2.h"
#include "L2/L2_ARP.h"
#include "L1/NIC.h"

using namespace std;

void main(int argc, char* argv[]) {

	// Declaring the client 
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "ip src 10.0.0.10 or arp");

	// Declaring the client's datalink layer
	L2_impl datalink_client(inet_client);

	// Setting up the client.
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();

	// Declaring the ARP of the client.
	L2_ARP_impl arp_client(inet_client, 10, 10000);

	// Declaring the server
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "ip src 10.0.0.15 or arp");

	// Declaring the server's datalink layer
	L2_impl datalink_server(inet_server);

	// Declaring the ARP of the server.
	L2_ARP_impl arp_server(inet_server, 10, 10000);

	// Setting up the server.
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L4_TCP_impl(inet_server), protosw::SWPROTO_TCP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();

	// Sniffer spawning.
	inet_client.connect(0U);
	inet_server.connect(0U);

	// Create a SOCKET for listening.
	netlab::L5_socket_impl* listenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	// Set up the client address structure
	struct sockaddr_in client_service;
	client_service.sin_family = AF_INET;
	client_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	client_service.sin_port = htons(8888);

	// Set up the server address structure
	sockaddr_in server_service;
	server_service.sin_family = AF_INET;
	server_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	server_service.sin_port = htons(8888);

	listenSocket->bind((SOCKADDR*)&server_service, sizeof(server_service));
	listenSocket->listen(5);

	// Create a SOCKET for connecting to server.
	netlab::L5_socket_impl* connectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	std::string send_msg("TCP Commuunication");
	size_t size = send_msg.size();
	std::string received_message;
	received_message.resize(size);

	connectSocket->connect((SOCKADDR*)&client_service, sizeof(client_service));

	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl* acceptSocket = nullptr;
	acceptSocket = listenSocket->accept(nullptr, nullptr);

	netlab::L5_socket_impl* ConnectSocket = connectSocket;
	std::thread([ConnectSocket, send_msg, size]()
	{
		ConnectSocket->send(send_msg, size, 1024);
	}).detach();

	std::string ret("");
	int byte_recived = acceptSocket->recv(ret, size, 3);

	std::this_thread::sleep_for(std::chrono::seconds(1));

	connectSocket->shutdown(SD_SEND);
	listenSocket->shutdown(SD_RECEIVE);
}