#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>


#include "pch.h"


#include "BaseTest.hpp"


bool system_socket_test = true;

class UDPTests : public test_base {

protected:

	inet_os system_inet;


	NIC system_nic;


	// Create a SOCKET for listening for incoming connection requests.
	netlab::L5_socket_impl* ServerSocket;
	// Create a SOCKET for connecting to server.
	netlab::L5_socket_impl* ClientSocket;

	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
	sockaddr_in service;

	UDPTests() : test_base("",""),
		system_nic(system_inet, nullptr, "", nullptr, nullptr, true, "")
	{

	}

	void SetUp() override {
		// Setting up the server.
		inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);				 
		inet_server.inetsw(new L4_UDP_Impl(inet_server), protosw::SWPROTO_UDP);				
		inet_server.inetsw(new L3_impl(inet_server,	SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);			
		inet_server.domaininit();


		// Setting up the client.
		inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
		inet_client.inetsw(new L4_UDP_Impl(inet_client), protosw::SWPROTO_UDP);
		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
		inet_client.domaininit();

		// Sniffer spawning.
		inet_client.connect(0U);
		// Sniffer spawning.
		inet_server.connect(0U);
	}

};

TEST_F(UDPTests, test_sender) {

	std::cout << "Initiating sender small packet test" << std::endl;

	int receivefrom_result(0);

	//----------------------
	// Create a SOCKET for the system server to receive datagrams
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//----------------------
	// Create a SOCKET for the server to receive datagrams
	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));

	//----------------------
	// Create a SOCKET for the client to send datagrams
	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));

	//----------------------
	// Insert corresponding addresses into arp cache
	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

	// Set up the server address structure
	struct sockaddr_in systen_server_service;
	systen_server_service.sin_family = AF_INET;
	systen_server_service.sin_addr.s_addr = inet_addr(my_ip.c_str());
	systen_server_service.sin_port = htons(9999);       // Port number

	// Set up the server address structure
	struct sockaddr_in server_service;
	server_service.sin_family = AF_INET;
	server_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	server_service.sin_port = htons(8888);       // Port number

	// Set up the server address structure
	struct sockaddr_in server_service_2;
	server_service_2.sin_family = AF_INET;
	server_service_2.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	server_service_2.sin_port = htons(8888);       // Port number

	// Set up the client address structure
	sockaddr_in system_client_service;
	system_client_service.sin_family = AF_INET;
	system_client_service.sin_addr.s_addr = inet_addr(my_ip.c_str());
	system_client_service.sin_port = htons(9999);

	// Set up the client address structure
	sockaddr_in client_service;
	client_service.sin_family = AF_INET;
	client_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	client_service.sin_port = htons(8888);

	// Bind the socket to the server address
	bind(server_socket, (struct sockaddr*)&systen_server_service, sizeof(systen_server_service));

	ServerSocket->bind((SOCKADDR*)&server_service, sizeof(server_service));

	std::string send_msg(32, 'T');
	std::string received_message;
	std::string ret_msg_from_os;
	received_message.resize(send_msg.size());
	ret_msg_from_os.resize(send_msg.size());
	size_t size = send_msg.size();

	netlab::L5_socket_impl* client_socket = ClientSocket;
	std::thread([client_socket, send_msg, size, system_client_service, client_service]()
	{
		client_socket->sendto(send_msg, size, 0, 0, (sockaddr*)&system_client_service, sizeof(system_client_service));
		client_socket->sendto(send_msg, size, 0, 0, (sockaddr*)&client_service, sizeof(client_service));

	}).detach();

	int* fromlen = new int(sizeof(systen_server_service));
	receivefrom_result = recvfrom(server_socket, &ret_msg_from_os[0], size, 0, (sockaddr*)&systen_server_service, fromlen);
	ServerSocket->recvfrom(received_message, size, 0, 0, (sockaddr*)&server_service_2, sizeof(server_service_2));

	ASSERT_EQ(receivefrom_result, size);
	ASSERT_EQ(received_message, send_msg);
	ASSERT_EQ(ret_msg_from_os, received_message);

	std::cout << "PASSED sender small packet test" << std::endl;

	ClientSocket->shutdown(SD_RECEIVE);
	ServerSocket->shutdown(SD_RECEIVE);

	// Close server socket
	closesocket(server_socket);
	WSACleanup();
}

TEST_F(UDPTests, test_receiver) {

	std::cout << "Initiating receiver small packet test" << std::endl;
	
	//----------------------
	// Create a SOCKET for the server to receive datagrams
	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));

	//----------------------
	// Create a SOCKET for the client to send datagrams
	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));

	//----------------------
	// Create a SOCKET for the system client to send datagrams
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET system_client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//----------------------
	// Insert corresponding addresses into arp cache
	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

	// Set up the client address structure (the sender in test_sender)

	struct sockaddr_in client_service;
	client_service.sin_family = AF_INET;
	client_service.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
	client_service.sin_port = htons(5000);       // Port number

	struct sockaddr_in client_service2;
	client_service2.sin_family = AF_INET;
	client_service2.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
	client_service2.sin_port = htons(5000);       // Port number

	// Set up the server address structure (our sending socket, back with an answer to the client)
	sockaddr_in server_service;
	server_service.sin_family = AF_INET;
	server_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	server_service.sin_port = htons(8888);

	ClientSocket->bind((SOCKADDR*)&client_service, sizeof(client_service));
	ServerSocket->bind((SOCKADDR*)&server_service, sizeof(server_service));

	std::string send_msg(32, 'T');
	std::string received_message;
	std::string system_received_message;
	received_message.resize(send_msg.size());
	system_received_message.resize(send_msg.size());
	size_t size = send_msg.size();

	ServerSocket->sendto(send_msg, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ClientSocket->recvfrom(received_message, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ASSERT_EQ(received_message, send_msg);

	std::thread([system_client_socket, send_msg, size, client_service2, client_service]()
		{
			int sendto_result(0);
			sendto_result = sendto(system_client_socket, &send_msg[0], size, 0, (sockaddr*)&client_service2, sizeof(client_service2));
			ASSERT_EQ(sendto_result, size);

		}).detach();

	ClientSocket->recvfrom(system_received_message, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ASSERT_EQ(system_received_message, send_msg);

	std::cout << "PASSED receiver small packet test" << std::endl;

	ClientSocket->shutdown(SD_RECEIVE);
	ServerSocket->shutdown(SD_RECEIVE);

	// Close client system socket
	closesocket(system_client_socket);
	WSACleanup();
}

TEST_F(UDPTests, test_receiver_bigPacket) {

	std::cout << "Initiating receiver big packet test" << std::endl;
	
	//----------------------
	// Create a SOCKET for the server to receive datagrams
	ServerSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_server));

	//----------------------
	// Create a SOCKET for the client to send datagrams
	ClientSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_DGRAM, IPPROTO_UDP, inet_client));

	//----------------------
	// Create a SOCKET for the system client to send datagrams
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET system_client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//----------------------
	// Insert corresponding addresses into arp cache
	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

	// Set up the client address structure (the sender in test_sender)

	struct sockaddr_in client_service;
	client_service.sin_family = AF_INET;
	client_service.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
	client_service.sin_port = htons(5000);       // Port number

	struct sockaddr_in client_service2;
	client_service2.sin_family = AF_INET;
	client_service2.sin_addr.s_addr = inet_client.nic()->ip_addr().s_addr;
	client_service2.sin_port = htons(5000);       // Port number

	// Set up the server address structure (our sending socket, back with an answer to the client)
	sockaddr_in server_service;
	server_service.sin_family = AF_INET;
	server_service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	server_service.sin_port = htons(8888);

	ClientSocket->bind((SOCKADDR*)&client_service, sizeof(client_service));
	ServerSocket->bind((SOCKADDR*)&server_service, sizeof(server_service));

	std::string send_msg;
	for (int i = 0; i < 3500; i++)
	{
		send_msg += "hello world!";
	}
	
	std::string received_message;
	std::string system_received_message;
	received_message.resize(send_msg.size());
	system_received_message.resize(send_msg.size());
	size_t size = send_msg.size();

	ServerSocket->sendto(send_msg, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ClientSocket->recvfrom(received_message, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ASSERT_EQ(received_message, send_msg);

	std::thread([system_client_socket, send_msg, size, client_service2, client_service]()
		{
			int sendto_result(0);
			sendto_result = sendto(system_client_socket, &send_msg[0], size, 0, (sockaddr*)&client_service2, sizeof(client_service2));
			ASSERT_EQ(sendto_result, size);

		}).detach();

	ClientSocket->recvfrom(system_received_message, size, 0, 0, (SOCKADDR*)&client_service2, sizeof(client_service2));
	ASSERT_EQ(system_received_message, send_msg);
	std::cout << system_received_message << std::endl;
	std::cout << "PASSED receiver big packet test" << std::endl;

	ClientSocket->shutdown(SD_RECEIVE);
	ServerSocket->shutdown(SD_RECEIVE);

	// Close client system socket
	closesocket(system_client_socket);
	WSACleanup();
}
