#pragma once

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <chrono>

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


	test_base() :
		inet_server(),
		inet_client(),
		nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, ""),
		nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, ""),
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

	void TearDown() override
	{
		inet_client.stop_fasttimo();
		inet_client.stop_slowtimo();

		inet_server.stop_fasttimo();
		inet_server.stop_slowtimo();

	}

};