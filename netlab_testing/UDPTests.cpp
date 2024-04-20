#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>

#include "BaseTest.h"
#include "pch.h"

/******************************/
/* System socket test switch */
bool system_socket_test = false;
/******************************/

class UDP_Tests : public test_base {

protected:

	UDP_Tests() : test_base()
	{
	}

	// Receiver socket is OS / our impl
	// Sender socket is our impl
	void test_sender() {

		int receive_result(0);

		//----------------------
		// Insert corresponding addresses into arp cache
		arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
		arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

		service.sin_family = AF_INET;
		service.sin_addr.s_addr = inet_addr("10.100.102.3");
		service.sin_port = htons(8888);

		//----------------------
		// Create a system SOCKET for the server to receive datagrams.
		WSADATA wsaData;
		int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		SOCKET server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		//----------------------
		// The sockaddr_in structure specifies the address family,
		// IP address, and port for the socket that is being bound.
		sockaddr_in server_socket_addr;
		server_socket_addr.sin_family = AF_INET;
		server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		server_socket_addr.sin_port = htons(8888); // Port number

		// Bind the socket to the server address
		::bind(server_socket, (struct sockaddr*)&server_socket_addr, sizeof(server_socket_addr));

		////----------------------
		//// Create a SOCKET for the client
		ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));

		//----------------------
		// The sockaddr_in structure specifies the address family,
		// IP address, and port for the socket that is being bound.
		sockaddr_in server_socket_addr_for_client;
		server_socket_addr_for_client.sin_family = AF_INET;
		server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		server_socket_addr_for_client.sin_port = htons(8888);

		std::string send_msg_client;
		send_msg_client = "Client: Hi, I am Client!";
		int sender_addr_size = sizeof(service);
		std::string recv_msg;
		recv_msg = "";
		std::string recv_msg_system_socket;
		recv_msg = "";

		ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
		ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
		receive_result = recvfrom(server_socket, &recv_msg_system_socket[0], send_msg_client.size(), 0, (SOCKADDR*)&server_socket_addr_for_client, &sender_addr_size);

		ASSERT_NE(receive_result, SOCKET_ERROR);
		ASSERT_EQ(recv_msg, send_msg_client);
		ASSERT_EQ(recv_msg, recv_msg_system_socket);

		closesocket(server_socket);
		WSACleanup();

		std::cout << recv_msg << std::endl;
	}

	void run_all_test() {

		inet_server.inetsw(new L4_UDP_Impl(inet_server), protosw::SWPROTO_UDP);
		inet_server.domaininit();

		/*std::cout << "start recive test" << std::endl;

		test_reciver();

		std::cout << "pass recive test" << std::endl;*/

		std::cout << "start sender test" << std::endl;

		test_sender();

		std::cout << "pass sender test" << std::endl;

		//std::cout << "start big msg test" << std::endl;

		//test_big_packet();

		//std::cout << "pass big msg test" << std::endl;
	}
};

TEST_F(UDP_Tests, runTests)
{
	std::cout << "TEST UDP" << std::endl;
	run_all_test();
	std::cout << "PASS TEST UDP" << std::endl;
}

//class UDPTests : public testing::Test {
//
//protected:
//
//	/* Declaring the client and the server */
//	inet_os inet_server;
//	inet_os inet_client;
//
//	/* Declaring the NIC of the client and the server */
//	NIC nic_client;
//	NIC nic_server;
//
//	/* Declaring the Datalink of the client and the server using L2_impl*/
//	L2_impl datalink_client;
//	L2_impl datalink_server;
//
//	/* Declaring the ARP of the client and the server using L2_impl*/
//	L2_ARP_impl arp_server;
//	L2_ARP_impl arp_client;
//
//	// Create a SOCKET for listening for incoming connection requests.
//	netlab::L5_socket_impl* ServerSocket;
//	// Create a SOCKET for connecting to server.
//	netlab::L5_socket_impl* ClientSocket;
//
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
//	sockaddr_in service;
//
//	UDPTests()
//		: inet_server(),
//		inet_client(),
//		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "(arp and ether src bb:bb:bb:bb:bb:bb) or (udp port 5000 and not ether src aa:aa:aa:aa:aa:aa) or (ip src 10.0.0.15)"),
//		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "(arp and ether src aa:aa:aa:aa:aa:aa) or (udp port 8888 and not ether src bb:bb:bb:bb:bb:bb) or (ip src 10.0.0.10)"),
//		datalink_server(inet_server),
//		datalink_client(inet_client),
//		arp_server(inet_server, 10, 10000),
//		arp_client(inet_client, 10, 10000)
//	{
//
//	}
//
//	void SetUp() override {
//
//		if (!system_socket_test) {
//
//			// Setting up the server.
//			inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);				 
//			inet_server.inetsw(new L4_UDP_Impl(inet_server), protosw::SWPROTO_UDP);				
//			inet_server.inetsw(new L3_impl(inet_server,	SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);			
//			inet_server.domaininit();
//			
//			// Sniffer spawning.
//			inet_server.connect(0U);
//
//		}
//
//		// Setting up the client.
//		inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//		inet_client.inetsw(new L4_UDP_Impl(inet_client), protosw::SWPROTO_UDP);
//		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//		inet_client.domaininit();
//
//		arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//		arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//
//		// Sniffer spawning.
//		inet_client.connect(0U);
//	}
//
//	void TearDown() override {
//
//		std::this_thread::sleep_for(std::chrono::seconds(5));
//		inet_client.stop_fasttimo();
//		inet_client.stop_slowtimo();
//
//		inet_server.stop_fasttimo();
//		inet_server.stop_slowtimo();
//
//		if (!system_socket_test) {
//
//			ServerSocket->shutdown(SD_RECEIVE);
//		}
//	}
//};

//TEST_F(UDPTests, emptyTest) {
//
//	//---------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//}

//TEST_F(UDPTests, oneWay_noArp) {
//
//	//----------------------
//	// Insert corresponding addresses into arp cache
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	////----------------------
//	//// Bind the socket.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client;
//	send_msg_client = "Client: Hi, I am Client!";
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//}

//TEST_F(UDPTests, oneWay_Arp) {
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	////----------------------
//	//// Bind the socket.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client;
//	send_msg_client = "Client: Hi, I am Client!";
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//}

//TEST_F(UDPTests, bigPacket_noArp) {
//
//	//----------------------
//	// Insert corresponding addresses into arp cache
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	////----------------------
//	//// Bind the socket.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client = std::string(1000, 'a') + std::string(1000, 'b') + std::string(1000, 'c');
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout <<  recv_msg << std::endl;
//}

//TEST_F(UDPTests, bigPacket_Arp) {
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	////----------------------
//	//// Bind the socket.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client = std::string(1000, 'a') + std::string(1000, 'b') + std::string(1000, 'c');
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//}

//TEST_F(UDPTests, twoWay_noArp) {
//
//	//----------------------
//	// Insert corresponding addresses into arp cache
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in client_socket_addr;
//	client_socket_addr.sin_family = AF_INET;
//	client_socket_addr.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
//	client_socket_addr.sin_port = htons(5000);
//
//	////----------------------
//	//// Bind the sockets.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//	ClientSocket->bind((SOCKADDR*)&client_socket_addr, sizeof(service));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client;
//	send_msg_client = "Client: Hi, I am Client!";
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in client_socket_addr_for_server;
//	client_socket_addr_for_server.sin_family = AF_INET;
//	client_socket_addr_for_server.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
//	client_socket_addr_for_server.sin_port = htons(5000);
//
//	std::string send_msg_server;
//	send_msg_server = "Server: Hello there Client! I am the server.";
//	recv_msg = "";
//
//	ServerSocket->sendto(send_msg_server, send_msg_server.size(), 0, 0, (SOCKADDR*)&client_socket_addr_for_server, sizeof(service));
//	ClientSocket->recvfrom(recv_msg, send_msg_server.size(), 0, 0, (SOCKADDR*)&client_socket_addr_for_server, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//}

//TEST_F(UDPTests, twoWay_Arp) {
//
//	//----------------------
//	// Create a SOCKET for the server to receive datagrams
//	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));
//
//	////----------------------
//	//// Create a SOCKET for the client
//	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr;
//	server_socket_addr.sin_family = AF_INET;
//	server_socket_addr.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr.sin_port = htons(8888);
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in client_socket_addr;
//	client_socket_addr.sin_family = AF_INET;
//	client_socket_addr.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
//	client_socket_addr.sin_port = htons(5000);
//
//	////----------------------
//	//// Bind the sockets.
//	ServerSocket->bind((SOCKADDR*)&server_socket_addr, sizeof(service));
//	ClientSocket->bind((SOCKADDR*)&client_socket_addr, sizeof(service));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in server_socket_addr_for_client;
//	server_socket_addr_for_client.sin_family = AF_INET;
//	server_socket_addr_for_client.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	server_socket_addr_for_client.sin_port = htons(8888);
//
//	std::string send_msg_client;
//	send_msg_client = "Client: Hi, I am Client!";
//	std::string recv_msg;
//	recv_msg = "";
//
//	ClientSocket->sendto(send_msg_client, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//	ServerSocket->recvfrom(recv_msg, send_msg_client.size(), 0, 0, (SOCKADDR*)&server_socket_addr_for_client, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	sockaddr_in client_socket_addr_for_server;
//	client_socket_addr_for_server.sin_family = AF_INET;
//	client_socket_addr_for_server.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
//	client_socket_addr_for_server.sin_port = htons(5000);
//
//	std::string send_msg_server;
//	send_msg_server = "Server: Hello there Client! I am the server.";
//	recv_msg = "";
//
//	ServerSocket->sendto(send_msg_server, send_msg_server.size(), 0, 0, (SOCKADDR*)&client_socket_addr_for_server, sizeof(service));
//	ClientSocket->recvfrom(recv_msg, send_msg_server.size(), 0, 0, (SOCKADDR*)&client_socket_addr_for_server, sizeof(service));
//
//	std::cout << recv_msg << std::endl;
//}
