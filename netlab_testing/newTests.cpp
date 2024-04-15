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

class newTests : public ::testing::Test {

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

	newTests()
		: inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)"),
		datalink_server(inet_server),
		datalink_client(inet_client),
		arp_server(inet_server, 10, 10000),
		arp_client(inet_client, 10, 10000)
	{

	}

    void SetUp() override {
        

		

    }

    void TearDown() override {

		inet_client.stop_fasttimo();
		inet_client.stop_slowtimo();

		inet_server.stop_fasttimo();
		inet_server.stop_slowtimo();
		std::this_thread::sleep_for(std::chrono::seconds(1));

		ConnectSocket->shutdown(SD_SEND);
		ListenSocket->shutdown(SD_RECEIVE);
		std::this_thread::sleep_for(std::chrono::seconds(3));
		
    }
};

// Function representing the code block to be executed by each sending thread
void sendFunction(netlab::L5_socket_impl* connectSocket, const std::string& send_msg, int size) {
		std::cout << "Sending iteration: " << std::endl;
		connectSocket->send(send_msg, size, size);
}

// Function representing the code block to be executed by each receiving thread
void recvFunction(netlab::L5_socket_impl* AcceptSocket, int size) {
	std::string msg;
	msg.reserve(size);
	msg = "";
	std::cout << "Received iteration: " << endl;
	int len = AcceptSocket->recv(msg, size, 1);
	std::cout << "message length: " << len << std::endl;
}


TEST_F(newTests, Test01) {

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


	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 0.75, L0_buffer::uniform_real_distribution_args(0, 1), L0_buffer::OUTGOING));
	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::uniform_real_distribution_args(0, 1), L0_buffer::INCOMING));

	std::string send_msg(500 * 1024  , 'T');
	size_t size = send_msg.size();
	//std::string send_msg;
	//send_msg.reserve(size);
	//send_msg = string(size / 5, 'a') + string(size / 5, 'b') + string(size / 5, 'c') + string(size / 5, 'd') + string(size / 5, 'e');
	int num = 1;
	netlab::L5_socket_impl* connectSocket = this->ConnectSocket;
	std::thread aaa([connectSocket, send_msg, num]()
		{
			for (int i = 0; i < num; i++)
			{

				std::cout << "iteration:  " << i << endl;
				connectSocket->send(send_msg, send_msg.size());
				///std::this_thread::sleep_for(chrono::milliseconds(9500));

			}
			std::cout << "finish sending!!:  " << endl;

		});




	std::thread recv_thread([AcceptSocket, num, size]()
	{
		
		std::this_thread::sleep_for(chrono::milliseconds(300));
		for (int i = 0; i < num; i++)
		{
			string msg;
			//msg.reserve(size);
			msg = "";
			std::cout << "start recv iteration:  " << i << endl;
			int len = AcceptSocket->recv(msg, size, 1);
			std::cout << "iteration:  " << i << "recived msg len  " << len << endl;
			//std::this_thread::sleep_for(chrono::milliseconds(7000));
			
		}
		std::cout << "finish recving!!:  " << endl;

	});


	// Vector to hold the thread objects for sending and receiving
	//std::vector<std::thread> threads;
	//// Create threads for sending
	//for (int i = 0; i < num; ++i) {
	//	threads.push_back(std::thread(sendFunction, connectSocket, send_msg, size));
	//	std::this_thread::sleep_for(chrono::milliseconds(10));
	//	threads.push_back(std::thread(recvFunction, AcceptSocket, size));
	//	std::this_thread::sleep_for(chrono::milliseconds(2800));
	//}

	//// Join all threads
	//for (auto& thread : threads) {
	//	thread.join();
	//}
	recv_thread.join();
	aaa.join();
//	std::this_thread::sleep_for(chrono::seconds(150));	
	//std::string ret("");
	//cout << "FF" << endl;
	//AcceptSocket->recv(ret, send_msg.size());
	std::cout << "finish" << endl;

}

//TEST_F(newTests, arpTest) {
//
//	//----------------------
//	// Before 3-way handshake, we expect the entry to be nullptr.
//	L2_ARP* arp_p = inet_client.arp();
//	auto entry = arp_p->arplookup(inet_server.nic()->ip_addr().s_addr, false);
//
//	ASSERT_EQ(entry, nullptr);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//	//----------------------
//	// Test if destination's address was saved in ARP cache.
//	
//	arp_p = inet_client.arp();
//	entry = arp_p->arplookup(inet_server.nic()->ip_addr().s_addr, false);
//	mac_addr expected_mac_addr("aa:aa:aa:aa:aa:aa");
//	cout << entry->getLaMac().to_string() << "       " << expected_mac_addr.to_string() << endl;
//	ASSERT_EQ(entry->getLaMac().to_string(), expected_mac_addr.to_string());
//
//	//-----------------------
//	// Test if packet is stored while the arp resolves the address.
//
//	/*do {
//		
//		ASSERT_EQ(entry->empty(), false);
//		std::this_thread::sleep_for(std::chrono::seconds(5));
//
//	} while (entry->valid());*/
//
//	//----------------------
//	// Test if saved entry was removed from cache as expected.
//	
//	std::this_thread::sleep_for(chrono::seconds((uint32_t)arp_p->getArptDown()));
//	entry = arp_p->arplookup(inet_server.nic()->ip_addr().s_addr, false);
//	
//	ASSERT_EQ(entry->valid(), false);
//}