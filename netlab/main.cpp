#include <WinSock2.h>
#include <iostream>

#include "L5/L5.h"
#include "L4/tcp_reno.h"
#include "L3/L3.h"
#include "L2/L2.h"
#include "L2/L2_ARP.h"
#include "L1/NIC.h"

using namespace std;

enum tcp_flavor {
	TCP_TAHOE,
	TCP_RENO
};

// Function to set the TCP flavor.
void set_tcp(inet_os& os, tcp_flavor tcp_type) {
	switch (tcp_type) {
	case TCP_TAHOE:
		os.inetsw(new tcp_tahoe(os), protosw::SWPROTO_TCP);
		break;
	case TCP_RENO:
		os.inetsw(new tcp_reno(os), protosw::SWPROTO_TCP);
		break;

	default:
		break;
	}
	os.domaininit();
}

void main(int argc, char* argv[]) {

	// Set the TCP flavor
	tcp_flavor tcp_type = TCP_TAHOE; // TCP_TAHOE or TCP_RENO

	// Declaring the client 
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "ip src 10.0.0.10 or arp");

	// Declaring the client's datalink layer
	L2_impl datalink_client(inet_client);

	// Setting up the client's network layer.
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);

	// Setting up the client's transport layer (TCP flavor).
	set_tcp(inet_client, tcp_type);

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
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);

	// Setting up the server's transport layer (TCP flavor).
	set_tcp(inet_server, tcp_type);

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
	connectSocket->connect((SOCKADDR*)&client_service, sizeof(client_service));

	// Create the message to send.
	std::string send_msg(500 * 1024, 'T');
	size_t size = send_msg.size();

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