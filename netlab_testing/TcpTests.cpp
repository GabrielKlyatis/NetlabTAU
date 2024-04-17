#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <chrono>

#include "pch.h"

using namespace std;

typedef netlab::HWAddress<> mac_addr;

class TCP_Tests : public testing::Test {

protected:

	/* Declaring the client and the server */
	inet_os inet_server;
	inet_os inet_client;

	/* Declaring the NIC of the client and the server */
    NIC nic_client;
    NIC nic_server;

	/* Declaring the Datalink of the client and the server using L2_impl*/
    L2_impl datalink_client;
    L2_impl datalink_server;

	/* Declaring the ARP of the client and the server using L2_impl*/
    L2_ARP_impl arp_server;
    L2_ARP_impl arp_client;
	
	// Create a SOCKET for listening for incoming connection requests.
    netlab::L5_socket_impl* ListenSocket;
	// Create a SOCKET for connecting to server.
    netlab::L5_socket_impl* ConnectSocket;
	// Create a SOCKET for accepting incoming requests.
    netlab::L5_socket_impl* AcceptSocket;

	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
	sockaddr_in service;
	sockaddr_in clientService;

	TCP_Tests()
		: inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, ""),
		datalink_server(inet_server),
		datalink_client(inet_client),
		arp_server(inet_server, 10, 10000),
		arp_client(inet_client, 10, 10000)
	{

	}

    void SetUp() override {
        

		

    }

    void TearDown() override {

		

		//ConnectSocket->shutdown(SD_SEND);
		//ListenSocket->shutdown(SD_RECEIVE);
	//	std::this_thread::sleep_for(std::chrono::seconds(2));

		//inet_client.stop_fasttimo();
		//inet_client.stop_slowtimo();

		//inet_server.stop_fasttimo();
		//inet_server.stop_slowtimo();
		//std::this_thread::sleep_for(std::chrono::seconds(1));



		
    }



};

void handleConnections(SOCKET server_socket, size_t expected_bytes) {
	struct sockaddr_in client_addr;
	int client_addr_len = sizeof(client_addr);
	int total = 0;
	char* a = new char[expected_bytes];
	std::fill(a, a + expected_bytes, 'T');


	while (true) {
		// Accept incoming connections
		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
			return;
		}

		std::cout << "Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;

		// Receive data from the client
		char* buffer = new char[expected_bytes];
		memset(buffer, 0, expected_bytes); // Clear the buffer (optional
		int bytes_received;
		while ((bytes_received = recv(client_socket, buffer + total, sizeof(buffer), 0)) > 0) {
			total += bytes_received;
			if (total >= expected_bytes)
			{
				break;
			}
		}

		std::cout << "Total bytes received: " << total << endl;
		auto c = memcmp(buffer, a, expected_bytes);
		if (memcmp(buffer, a, expected_bytes) == 0)
		{
			std::cout << "Data received successfully" << std::endl;
		}
		else
		{
			std::cerr << "Data received is corrupted" << std::endl;
		}

		// Check if recv failed
		if (bytes_received == SOCKET_ERROR) {
			std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
		}

		// Close client socket
		closesocket(client_socket);
		delete buffer;
		delete a;
		break;
	}
}



TEST_F(TCP_Tests, test02)
{

	L2_impl datalink_client(inet_client);
	L2_ARP_impl arp_client(inet_client, 10, 10000);
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	//arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());


	inet_client.connect();

	sockaddr_in service;
	ConnectSocket = new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client);

	sockaddr_in client_service;
	client_service.sin_family = AF_INET;
	client_service.sin_addr.s_addr = inet_addr("192.168.1.239");
	client_service.sin_port = htons(8888);

	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Set up the server address structure
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
	server_addr.sin_port = htons(8888);       // Port number
	// Bind the socket to the server address
	::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));

	// Listen for incoming connections
	listen(server_socket, SOMAXCONN);

	std::cout << "Server listening on port 8888..." << std::endl;

	std::string send_msg(1000 * 50, 'T');
	size_t size = send_msg.size();

	// Create a thread to handle incoming connections
	std::thread connectionThread(handleConnections, server_socket, size);

	ConnectSocket->connect((SOCKADDR*)&client_service, sizeof(client_service));
	netlab::L5_socket_impl* client_socket = ConnectSocket;
	std::thread([client_socket, send_msg, size]()
	{
			client_socket->send(send_msg, size, 1024);
		std::cout << "finish shending" << std::endl;
	}).detach();

	connectionThread.join();
	std::cout << "fin" << std::endl;
	// Close server socket
	closesocket(server_socket);
	WSACleanup();

	ConnectSocket->shutdown(SD_SEND);
	//ListenSocket->shutdown(SD_RECEIVE);
	std::this_thread::sleep_for(std::chrono::seconds(2));
	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
	std::this_thread::sleep_for(std::chrono::seconds(2));
}


TEST_F(TCP_Tests, Test01) {

	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

	/* Declaring protocols is a bit different: */
	inet_server.inetsw(
		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
	inet_server.inetsw(
		new tcp_reno(inet_server),		// Defining the TCP Layer using my tcp_reno
		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
	inet_server.inetsw(
		new L3_impl(						// The actual IP layer we will use.
			inet_server,						// Binding this NIC to our server
			SOCK_RAW,							// The protocol type
			IPPROTO_RAW,						// The protocol
			protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.

	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.

	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address


	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());

	/* Spawning both sniffers, 0U means continue forever */
	inet_server.connect(0U);
	inet_client.connect(0U);


	// The socket address to be passed to bind

	//----------------------
	// Create a SOCKET for listening for 
	// incoming connection requests
	ListenSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound.
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	service.sin_port = htons(8888);

	////----------------------
	//// Bind the socket.
	ListenSocket->bind((SOCKADDR*)&service, sizeof(service));

	////----------------------
	//// Listen for incoming connection requests 
	//// on the created socket
	//// 
	ListenSocket->listen(5);

	////----------------------
	//// Create a SOCKET for connecting to server
	ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = htons(8888);


	//----------------------
	// Connect to server.
	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));

	//----------------------
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl* AcceptSocket = nullptr;

	//----------------------
	// Accept the connection.
	AcceptSocket = ListenSocket->accept(nullptr, nullptr);


	inet_server.cable()->set_buf(new L0_buffer(inet_server, 0.75, L0_buffer::uniform_real_distribution_args(0, 0.001), L0_buffer::OUTGOING));
	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::uniform_real_distribution_args(0, 1), L0_buffer::INCOMING));

	std::string send_msg(500 * 1024  , 'T');
	size_t size = send_msg.size();
	//std::string send_msg;
	//send_msg.reserve(size);
	//send_msg = string(size / 5, 'a') + string(size / 5, 'b') + string(size / 5, 'c') + string(size / 5, 'd') + string(size / 5, 'e');

	netlab::L5_socket_impl* connectSocket = this->ConnectSocket;
	std::thread([connectSocket, send_msg, size]()
	{
		connectSocket->send(send_msg, size, 1024);
		std::cout << "finish shending" << std::endl;
	}).detach();
		//ConnectSocket->send(send_msg, size, 512);
	std::string ret("");

	int a = AcceptSocket->recv(ret, size, 3);
	//std::cout << a << ret << std::endl;

	std::cout << ret.size() << std::endl;


	std::cout << "finish" << endl;

}


