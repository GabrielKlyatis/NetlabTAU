#pragma once

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <chrono>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>


#pragma comment(lib, "Ws2_32.lib")
#include "pch.h"

typedef netlab::HWAddress<> mac_addr;

class test_base : public testing::Test
{
public:

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

	/*TCP*/

	// Create a SOCKET for listening for incoming connection requests.
	netlab::L5_socket_impl* ListenSocket;
	// Create a SOCKET for connecting to server.
	netlab::L5_socket_impl* ConnectSocket;
	// Create a SOCKET for accepting incoming requests.
	netlab::L5_socket_impl* AcceptSocket;

	/*UDP*/

	// Create a SOCKET for listening for incoming connection requests.
	netlab::L5_socket_impl* ServerSocket;
	// Create a SOCKET for connecting to server.
	netlab::L5_socket_impl* ClientSocket;

	// The sockaddr_in structure specifies the address family,
	// IP address, and port for the socket that is being bound (SERVER)/and port of the server to be connected to (CLIENT).
	sockaddr_in service;
	sockaddr_in clientService;

	std::string my_ip;
	

	test_base(std::string client_filter, std::string server_filter) : my_ip(get_my_ip()),
		inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, (server_filter == "") ? "" : server_filter + test_base::get_default_flilter()),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, (client_filter == "") ? "" : client_filter + test_base::get_default_flilter()),
		datalink_server(inet_server),
		datalink_client(inet_client),
		arp_server(inet_server, 10, 10000),
		arp_client(inet_client, 10, 10000)
	{
		inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);


	}

	void SetUp() override
	{
		inet_server.connect(0U);
		inet_client.connect(0U);
	}

	void TearDown() override {


		//std::this_thread::sleep_for(std::chrono::seconds(2));

		inet_client.stop_fasttimo();
		inet_client.stop_slowtimo();

		inet_server.stop_fasttimo();
		inet_server.stop_slowtimo();

		std::this_thread::sleep_for(std::chrono::milliseconds(450));

	}


	static std::string get_my_ip() {
		WSADATA wsaData;
		char ac[80];

		// Initialize Winsock
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
			return "";
		}

		// Get the host name
		if (gethostname(ac, sizeof(ac)) == SOCKET_ERROR) {
			std::cerr << "Error " << WSAGetLastError() << " when getting local host name." << std::endl;
			WSACleanup();
			return "";
		}

		// Get address information using getaddrinfo()
		struct addrinfo hints, * res = nullptr;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;  // Use AF_INET for IPv4 addresses
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(ac, nullptr, &hints, &res) != 0) {
			std::cerr << "getaddrinfo failed: " << WSAGetLastError() << std::endl;
			WSACleanup();
			return "";
		}

		// Loop through the results and convert the first IPv4 address to a string
		for (struct addrinfo* ptr = res; ptr != nullptr; ptr = ptr->ai_next) {
			if (ptr->ai_family == AF_INET) {  // Only use IPv4 addresses
				struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
				char ipstr[INET_ADDRSTRLEN] = { 0 };
				inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipstr, sizeof(ipstr));

				freeaddrinfo(res);  // Clean up
				WSACleanup();       // Clean up Winsock
				return std::string(ipstr);  // Return the first IP address found
			}
		}

		// Cleanup
		freeaddrinfo(res);
		WSACleanup();

		return "";
	}
	static std::string get_default_flilter()
	{
		std::string filter = " or ip src " + get_my_ip() + " or arp";
		return filter;
	}

	//virtual std::string get_server_filter() = 0;
	//virtual std::string get_clinet_filter() = 0;
};

