//#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
//#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#endif
//#include <iostream>
//#include <algorithm>
//#include "L2/L2.h"
//#include "L3/L3.h"
//#include "L4/L4_TCP.h"
//#include "L1/NIC.h"
//#include "L2/L2_ARP.h"
//#include "L1/NIC_Cable.h"
//#include "L0/L0_buffer.h"
//#include "L4/tcp_reno.h"
//#include "L4/tcp_tahoe.h"
//#include "L5/tls_socket.h"
//#include <openssl/ssl.h>
//#include <iostream>
//#include <iomanip>
//#include <vector>
//#include <string>
//#include <cstdlib>
//#include <pthread.h>
//using namespace std;
//
//
//void test1() 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();	
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void test2() 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void test3(size_t size = 32, size_t num = 5) 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect();
//	inet_client.connect();
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	std::string send_msg(size, 'T');
//	std::thread([ConnectSocket, send_msg, num, size]()
//	{
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//
//		for (size_t i = 0; i < num; i++)
//		{
//			ConnectSocket->send(send_msg, size, size);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//
//	}).detach();
//
//	typedef std::chrono::nanoseconds nanoseconds;
//	typedef std::chrono::duration<double> seconds;
//	typedef std::random_device generator;
//	generator gen;
//	std::exponential_distribution<> dist(3);
//	std::string ret("");
//	for (size_t i = 0; i < num; i++)
//	{
//		AcceptSocket->recv(ret, size);
//		std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//	}
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//}
//
//void handleConnections(SOCKET server_socket, size_t expected_bytes) {
//	struct sockaddr_in client_addr;
//	int client_addr_len = sizeof(client_addr);
//	int total = 0;
//	char* a = new char[expected_bytes];
//	std::fill(a, a + expected_bytes, 'T');
//
//
//	while (true) {
//		// Accept incoming connections
//		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
//		if (client_socket == INVALID_SOCKET) {
//			std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
//			return;
//		}
//
//		std::cout << "Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
//
//		// Receive data from the client
//		char* buffer = new char[expected_bytes];
//		memset(buffer, 0, expected_bytes); // Clear the buffer (optional
//		int bytes_received;
//		while ((bytes_received = recv(client_socket, buffer + total, sizeof(buffer), 0)) > 0) {
//			// Process received data (here, we just print it)
//			//buffer[bytes_received] = '\0'; // Null-terminate the received data
//			//std::cout << "Received from client " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << ": " << buffer << std::endl;
//			total +=bytes_received;
//			if (total >= expected_bytes)
//			{
//				break;
//			}
//		}
//		
//		std::cout << "Total bytes received: " << total << endl;	
//		auto c = memcmp(buffer, a, expected_bytes);
//		if (memcmp(buffer, a, expected_bytes) == 0)
//		{
//			std::cout << "Data received successfully" << std::endl;
//		}
//		else
//		{
//			std::cerr << "Data received is corrupted" << std::endl;
//		}
//
//		// Check if recv failed
//		if (bytes_received == SOCKET_ERROR) {
//			std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
//		}
//
//		// Close client socket
//		closesocket(client_socket);
//		delete buffer;
//		delete a;
//		break;
//	}
//}
// 
//
//#include <iostream>
//
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/x509.h>
//#include <openssl/x509v3.h>
//#include <openssl/bn.h>
//#include <openssl/asn1.h>
//#include <openssl/x509_vfy.h>
//#include <openssl/bio.h>
//#include <openssl/rsa.h>
//#include <openssl/kdf.h>
//#include <stdexcept>
//#include <openssl/rand.h>
//#include <openssl/hmac.h>
//#include <openssl/evp.h>
//#include <random>
//#include <fstream>
//#include <openssl/aes.h>
//#include <stdio.h>
//#include <stdint.h>
//#include <WinSock2.h>
//#include <WS2tcpip.h>
//#include <openssl/hmac.h>
//#pragma comment(lib, "Ws2_32.lib")
//
//#pragma warning(disable : 4996)
//
//void print_hex(const unsigned char* buffer, size_t len) {
//	for (size_t i = 0; i < len; ++i) {
//		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
//	}
//	std::cout << std::endl;
//}
//// Function to convert a hexadecimal string to bytes
//std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
//	std::vector<unsigned char> bytes;
//
//	for (size_t i = 0; i < hex.length(); i += 2) {
//		unsigned int byte; 
//		std::istringstream(hex.substr(i, 2)) >> std::hex >> byte;
//		bytes.push_back(static_cast<unsigned char>(byte));
//	}
//
//	return bytes;
//}
//
//int aaaa()
//{
//	// Initialize OpenSSL
//	SSL_library_init();
//	SSL_load_error_strings();
//	OpenSSL_add_all_algorithms();
//
//	std::string cr = "017dcc4e3542755665d8605b516d5b7632adf80458742fb525a6276a982448fe";
//	std::string sr = "77731af81550abb2c20da0c4a7b73c09a43afa660a512313806af59d4b33a75a";
//
//	std::string hexString = "030373e4360fb365c20682e03ff197d2de5db2c001985a54de392339ee68dcf81826facf9dd172569b170dd797ae25f3";
//
//	// Convert the hexadecimal string to bytes
//	std::vector<unsigned char> bytes = hexStringToBytes(hexString);
//	std::vector<unsigned char> cl_r = hexStringToBytes(cr);
//	std::vector<unsigned char> sr_r = hexStringToBytes(sr);
//
//
//
//	std::string label = "master secret";
//	std::vector<uint8_t> seed;
//	seed.insert(seed.end(), label.begin(), label.end());
//	seed.insert(seed.end(), cl_r.begin(), cl_r.end());
//	seed.insert(seed.end(), sr_r.begin(), sr_r.end());
//	
//	// create master sercret 
//	EVP_PKEY_CTX* pctx;
//
//	uint8_t master_secret1[48];
//	size_t len = 48;
//
//	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
//	if (EVP_PKEY_derive_init(pctx) <= 0) return 1;
//	if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) return 1;
//	if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, bytes.data(), 48) <= 0) return 1;
//	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seed.size()) <= 0) return 1;
//	if (EVP_PKEY_derive(pctx, master_secret1, &len) <= 0) return 1;
//	//EVP_PKEY_CTX_free(pctx);
//
//	
//
//	// key derive
//
//	std::string label1 = "key expansion";
//	std::vector<uint8_t> seed1;
//	seed1.insert(seed1.end(), label1.begin(), label1.end());
//	
//	seed1.insert(seed1.end(), sr_r.begin(), sr_r.end());
//	seed1.insert(seed1.end(), cl_r.begin(), cl_r.end());
//
//	uint8_t key_block[104];
//	size_t len1 = 104;
//	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
//	if (EVP_PKEY_derive_init(pctx) <= 0) return 1;
//	if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) return 1;
//	if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, master_secret1, 48) <= 0) return 1;
//	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1.data(), seed1.size()) <= 0) return 1;
//	if (EVP_PKEY_derive(pctx, key_block, &len1) <= 0) return 1;
////	EVP_PKEY_CTX_free(pctx);
//
//
//	// Extract keys and IVs from key_block
//	unsigned char client_write_MAC[20];   // MAC key size (SHA-1)
//	unsigned char server_write_MAC[20];   // MAC key size (SHA-1)
//	unsigned char client_write_key[16];   // Encryption key size (AES-128)
//	unsigned char server_write_key[16];   // Encryption key size (AES-128)
//	unsigned char client_write_IV[16];    // IV size
//	unsigned char server_write_IV[16];    // IV size
//
//	unsigned char* ptr = key_block;
//	memcpy(client_write_MAC, ptr, 20);    ptr += 20;
//	memcpy(server_write_MAC, ptr, 20);    ptr += 20;
//	memcpy(client_write_key, ptr, 16);    ptr += 16;
//	memcpy(server_write_key, ptr, 16);    ptr += 16;
//	memcpy(client_write_IV, ptr, 16);     ptr += 16;
//	memcpy(server_write_IV, ptr, 16);     ptr += 16;
//
//
//	// compute verify data
//	std::string clinet_hello = "010000610303017dcc4e3542755665d8605b516d5b7632adf80458742fb525a6276a982448fe000004002f00ff01000034000d0030002e04030503060308070808081a081b081c0809080a080b080408050806040105010601030303010302040205020602";
//	std::string server_hello = "0200004d030377731af81550abb2c20da0c4a7b73c09a43afa660a512313806af59d4b33a75a201a2a02b0ab5af2c6321b614f19dd7607b407bd67ecb7fd6ddbf001b21a76c786002f000005ff01000100";
//	std::string cartificate = "0b00035b0003580003553082035130820239a00302010202147769659ad6801964a495f1c44f00d8c7b94c7cad300d06092a864886f70d01010b050030383113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3234303530383135303634385a170d3235303530383135303634385a30383113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100b44af72642a9845a4c60c9e7d89f2da81adcb0b0cd57a6932da00c9e10d339163bafb72e81c5b8ee7ba323c5dfd2bbf2e93b161eb93d9c233fff1d48a90613a84859417a2c9ad472a9da96ed946c1926cf30ab69574d2893fbb9587bc16132e285c691355e8d6b034cc0447eeb3fd849e2a3f94a619f0ea51d89d079dac2f6c8c434fc722ac001beb458417e15f02b47fe30c417484dc72441893e3ffaf18472dccce8ef43b9c4f19ef6d489e10e969411f4de1c19f9784fcaa02b77eae7b1ddbb4f6e72c209f51f112c58375ac138736277f581f1ad8a14c2087e890e008150b255ef582bbb0e1e3b006875a5b28ec413efe143a68351d96aa3498ae6b5eab30203010001a3533051301d0603551d0e041604148b3c6eb542bb32dfd353b549b6b048606a5b3299301f0603551d230418301680148b3c6eb542bb32dfd353b549b6b048606a5b3299300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100099e5277b9985afa8f725ff82f53a2bbe281652b3f0bf66139310489ed3de04be6a578b951ae72241ca963d85ab4cc314b89b37b0db0d19b32291ee7fb816907a0e8a6fd03f3036451dc692bb5ba09a07290e8d3a8d51f07b68e5e16a1f67e3ddc77fdddb71e3c08f50b60cf2b571e8b3413f0ac43786231c382a7bdcfec9c4aa8a8b5670ba2a32088ce97bd92290e476951f033edfe4abf921fbe5e4229191adc4a7861d76b7da4b1384260400ffd193703ed723994ed9c76449b5b6b58ea8440a7ca8e97044d0914b47e5c0d74be177f65fdb803c27c2280192fe1910c618c73aaee4c5ba76a7d9732314cf4879399bad39ba831a8ce9c84a2e7ac86072369";
//	std::string server_hello_done = "0e000000";
//	std::string client_key_exchange = "1000010201005ff2a42dea2ddde17dbaeed6e716d5fd2dfe1a29d044fa7581bf0745e512f33dbf37f23db0220844e863274175d36ea2746e8fb39548c0766c99d622903bfe1ee8d8ef633bb8bdc70047358e9f457ab88d59458dfcab28ef6e7841fe8900e4bbc76e6f0cb382bd55ac3dab7740a582ef4899a32fec1044e07843be275e1a292e670a92ea7bbe27b11d6bacc4e61d23c975779b114c12770191a034b07019fd00a6afcf970e3064dacb05786a460ee4a3c125b42c4d3b6fbc0ae382d4de90ffd36ec45353645596758b528fdb087ac3b37fb222ce0e2296f1f91553411fb08f269ab98cc47d6e2918d3ea25203212e030cbec6c8c145f86259556567d7910865c";
//	std::string client_finished = "client finished";
//	std::string concatenated =clinet_hello + server_hello + cartificate + server_hello_done + client_key_exchange;
//	std::vector<uint8_t> conc = hexStringToBytes(concatenated);
//
//	uint8_t hash_msg[32];
//	SHA256(conc.data(), conc.size(), hash_msg);
//
//	std::vector<uint8_t> seed2;
//	seed2.insert(seed2.end(), client_finished.begin(), client_finished.end());
//	seed2.insert(seed2.end(), hash_msg, hash_msg + 32);
//	
//
//	uint8_t verify_data[12];
//	size_t len2 = 12;
////	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
//	if (EVP_PKEY_derive_init(pctx) <= 0) return 1;
//	if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) return 1;
//	if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, master_secret1, 48) <= 0) return 1;
//	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2.data(), seed2.size()) <= 0) return 1;
//	if (EVP_PKEY_derive(pctx, verify_data, &len2) <= 0) return 1;
//	//EVP_PKEY_CTX_free(pctx);
//
//
//
//	std::vector<uint8_t> final_msg = {0x14, 0x00 , 0x00 , 0x0c};
//	final_msg.insert(final_msg.end(), verify_data, verify_data + 12);
//	uint8_t pre[32];
//	unsigned int a;
//
//
//
//	std::vector<uint8_t> to_mac;
//	uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//	uint8_t rest[5] = { 0x16, 0x03, 0x03 };  // Handshake type 0x16, version 0x0303 (TLS 1.2)
//
//	// Correct length (high byte, low byte)
//	uint16_t length = final_msg.size();
//	rest[3] = (length >> 8) & 0xff;
//	rest[4] = length & 0xff;
//
//	to_mac.insert(to_mac.end(), seq_bym, seq_bym + sizeof(seq_bym));
//	to_mac.insert(to_mac.end(), rest, rest + sizeof(rest));
//	to_mac.insert(to_mac.end(), final_msg.begin(), final_msg.end());
//
//
//	// Compute HMAC-SHA1
//	unsigned char mac[20];
//	unsigned int mac_len;
//	HMAC(EVP_sha1(),client_write_MAC, 20, to_mac.data(), to_mac.size(), mac, &mac_len);
//	
//	final_msg.insert(final_msg.end(), mac, mac + 20);
//	// add pad
//	uint8_t pad = 0x0b;
//	for (uint8_t i = 0; i < pad; i++)
//	{
//		final_msg.push_back(pad);
//	}
//	final_msg.push_back(pad);
//
//	// Encrypt the padded message
//	EVP_CIPHER_CTX* ctx3 = EVP_CIPHER_CTX_new();
//	int s= EVP_CIPHER_CTX_reset(ctx3);
//	if (!ctx3) return 1;
//	
//	int lenn;
//	int ciphertext_len_temp = 0;
//	std::vector<uint8_t> ciphertext(100);  // Ensure the buffer is large enough
//
//	uint8_t iv[16] = {0x78, 0x48, 0x6a, 0x7b, 0xe7, 0x24, 0xbc, 0xcc, 0x29, 0x8b, 0x4c, 0x80, 0xe1, 0xcf, 0xeb, 0x4d};
//
//	if (EVP_EncryptInit_ex(ctx3, EVP_aes_128_cbc(), NULL, client_write_key, iv) != 1) {
//		ERR_print_errors_fp(stderr);
//		return 1;
//	}
//
//	if (EVP_EncryptUpdate(ctx3, ciphertext.data(), &lenn, final_msg.data(), final_msg.size()) != 1) {
//		ERR_print_errors_fp(stderr);
//		return 1;
//	}
//
//	ciphertext_len_temp = lenn;
//
//	if (EVP_EncryptFinal_ex(ctx3, ciphertext.data() + lenn, &lenn) != 1) {
//		ERR_print_errors_fp(stderr);
//		return 1;
//	}
//	ciphertext_len_temp += len;
//
//	EVP_CIPHER_CTX_free(ctx3);
//
//	// Truncate to the actual ciphertext length
//	ciphertext.resize(ciphertext_len_temp);
//
//
//	// Initialize Winsock
//	WSADATA wsaData;
//	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
//		std::cerr << "Error initializing Winsock" << std::endl;
//		return 1;
//	}
//
//	
//
//	// Create SSL context
//	SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_client_method());
//	if (!ctx) {
//		std::cerr << "Error creating SSL_CTX" << std::endl;
//		ERR_print_errors_fp(stderr);
//		WSACleanup();
//		return 1;
//	}
//
//
//	// Disable TLS extensions
//	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_ENCRYPT_THEN_MAC | SSL_OP_DISABLE_TLSEXT_CA_NAMES);
//
//	// Load trust store (optional)
//	if (!SSL_CTX_load_verify_locations(ctx, nullptr, "/etc/ssl/certs")) {
//		std::cerr << "Error loading trust store" << std::endl;
//		ERR_print_errors_fp(stderr);
//		SSL_CTX_free(ctx);
//		WSACleanup();
//		return 1;
//	}
//
//	// Create SSL object
//	SSL* ssl = SSL_new(ctx);
//	if (!ssl) {
//		std::cerr << "Error creating SSL structure" << std::endl;
//		ERR_print_errors_fp(stderr);
//		SSL_CTX_free(ctx);
//		WSACleanup();
//		return 1;
//	}
//
//	// Disable unnecessary extensions using SSL_ctrl
//	SSL_set_options(ssl, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
//
//	// Set cipher suite
//	if (SSL_set_cipher_list(ssl, "TLS_RSA_WITH_AES_256_CBC_SHA256") != 1) {
//		std::cerr << "Error setting cipher suite" << std::endl;
//		ERR_print_errors_fp(stderr);
//		SSL_free(ssl);
//		SSL_CTX_free(ctx);
//		WSACleanup();
//		return 1;
//	}
//	// Set the pre-master secret callback using a lambda function
//	
//
//	// Connect to server
//	SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//	if (sockfd == INVALID_SOCKET) {
//		std::cerr << "Error creating socket" << std::endl;
//		WSACleanup();
//		return 1;
//	}
//
//	struct sockaddr_in server_addr;
//	server_addr.sin_family = AF_INET;
//	server_addr.sin_port = htons(444);
//	inet_pton(AF_INET, "192.168.1.225", &server_addr.sin_addr);
//
//	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
//		std::cerr << "Error connecting to server" << std::endl;
//		closesocket(sockfd);
//		WSACleanup();
//		return 1;
//	}
//
//	SSL_set_fd(ssl, sockfd);
//
//	if (SSL_connect(ssl) != 1) {
//		std::cerr << "Error establishing SSL connection" << std::endl;
//		ERR_print_errors_fp(stderr);
//		SSL_free(ssl);
//		SSL_CTX_free(ctx);
//		closesocket(sockfd);
//		WSACleanup();
//		return 1;
//	}
//
//	// Print client random
//	std::cout << "Client Random: ";
//	unsigned char client_random[SSL3_RANDOM_SIZE];
//	SSL_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE);
//	print_hex(client_random, SSL3_RANDOM_SIZE);
//
//	// Print server random
//	std::cout << "Server Random: ";
//	unsigned char server_random[SSL3_RANDOM_SIZE];
//	SSL_get_server_random(ssl, server_random, SSL3_RANDOM_SIZE);
//	print_hex(server_random, SSL3_RANDOM_SIZE);
//
//	// Print pre-master secret
//	std::cout << "Pre-Master Secret: ";
//	unsigned char pre_master_secret[48];
//	int pre_master_len = SSL_get_peer_finished(ssl, pre_master_secret, 48);
//	if (pre_master_len <= 0) {
//		std::cerr << "Error getting pre-master secret" << std::endl;
//	}
//	else {
//		print_hex(pre_master_secret, pre_master_len);
//	}
//		
//	// Get master secret (only available after handshake)
//	SSL_SESSION* session = SSL_get_session(ssl);
//	
//	if (session) {
//		std::cout << "Master Secret: ";
//		unsigned char master_secret[48];
//		SSL_SESSION_get_master_key(session, master_secret, 48);
//		print_hex(master_secret, 48);
//	}
//	else {
//		std::cerr << "Error getting SSL session" << std::endl;
//	}
//
//	// Clean up
//	SSL_shutdown(ssl);
//	SSL_free(ssl);
//	SSL_CTX_free(ctx);
//	closesocket(sockfd);
//	WSACleanup();
//
//
//
//
//	return 0;
//	
//}
//
//using namespace netlab;
//
//void client_hello_serialization_test() {
//
//	inet_os inet_client = inet_os();
//	inet_os dflt = inet_os();
//	NIC nic_client(inet_client, "10.100.102.13", "a8:6d:aa:68:39:a4", nullptr, nullptr, true, "arp or ip src 10.100.102.4");
//	//NIC dflt_gtw(dflt, "192.168.1.1", "c8:70:23:14:46:ef", nullptr, nullptr, true, "");
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//	//arp_client.insertPermanent(dflt_gtw.ip_addr().s_addr, dflt_gtw.mac());
//	inet_client.connect();
//
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_addr("10.100.102.4");
//	clientService.sin_port = htons(443);
//
//	TLSHandshakeProtocol handshakeProtocol;
//
//	HandshakeType msg_type = CLIENT_HELLO;
//
//	handshakeProtocol.handshake.configureHandshakeBody(msg_type);
//
//	handshakeProtocol.updateHandshakeProtocol(msg_type);
//
//	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);
//
//	std::cout << "Serialization Test Begins:" << std::endl;
//
//	// Print the bytes
//	std::cout << "The string that is sent is : ";
//	for (size_t i = 0; i < serialized_string.size(); i++) {
//		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(serialized_string[i]);
//	}
//	std::cout << std::endl;
//
//	netlab::L5_socket_impl* ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//
//	ConnectSocket->send(serialized_string, serialized_string.size(), 0, 0);
//
//}
//
//void server_hello_serialization_test() {
//
//	inet_os inet_client = inet_os();
//	inet_os dflt = inet_os();
//	NIC nic_client(inet_client, "10.100.102.13", "a8:6d:aa:68:39:a4", nullptr, nullptr, true, "arp or ip src 10.100.102.4");
//	//NIC dflt_gtw(dflt, "192.168.1.1", "c8:70:23:14:46:ef", nullptr, nullptr, true, "");
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//	//arp_client.insertPermanent(dflt_gtw.ip_addr().s_addr, dflt_gtw.mac());
//	inet_client.connect();
//
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_addr("10.100.102.4");
//	clientService.sin_port = htons(443);
//
//	const char* cert_file = "C:/Projects/OpenSSL-Win32/certificate.crt";
//
//	FILE* fp = fopen(cert_file, "r");
//	if (!fp) {
//		fprintf(stderr, "unable to open: %s\n", cert_file);
//		// return EXIT_FAILURE;
//	}
//
//	X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
//	if (!cert) {
//		fprintf(stderr, "unable to parse certificate in: %s\n", cert_file);
//		fclose(fp);
//		//  return EXIT_FAILURE;  
//	}
//
//	unsigned char* buf;
//	buf = NULL;
//	uint32_t len = i2d_X509(cert, &buf);  // converting to unsigned char*
//
//	std::vector<uint8_t> cartificate(buf, buf + len);
//	fclose(fp);
//
//	TLSHandshakeProtocol handshakeProtocol;
//
//	HandshakeType msg_type = SERVER_HELLO;
//
//	handshakeProtocol.handshake.configureHandshakeBody(msg_type);
//
//	handshakeProtocol.updateHandshakeProtocol(msg_type);
//
//	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);
//	/************************************************************************/
//	msg_type = CERTIFICATE;;
//
//	handshakeProtocol.handshake.configureHandshakeBody(msg_type);
//
////	handshakeProtocol.handshake.body.certificate.addCertificate(cartificate);
//
//	handshakeProtocol.updateHandshakeProtocol(msg_type);
//
//	serialized_string.append(handshakeProtocol.serialize_handshake_protocol_data(msg_type));
//	/************************************************************************/
//	msg_type = SERVER_HELLO_DONE;
//
//	handshakeProtocol.handshake.configureHandshakeBody(msg_type);
//
//	handshakeProtocol.updateHandshakeProtocol(msg_type);
//
//	serialized_string.append(handshakeProtocol.serialize_handshake_protocol_data(msg_type));
//	/************************************************************************/
//	msg_type = CLIENT_KEY_EXCHANGE;
//
//	handshakeProtocol.handshake.configureHandshakeBody(msg_type);
//
//	// Create a BIO object from the TLS data
//	// Initialize OpenSSL
//	SSL_library_init();
//	OPENSSL_init_ssl(0, NULL);
//	OPENSSL_init_crypto(0, NULL);
//
//	// Create a BIO object to read the certificate
//	BIO* bio = BIO_new_mem_buf(&cartificate[3], cartificate.size() - 3);
//	if (!bio) {
//		std::cerr << "Error creating BIO" << std::endl;
//	}
//
//	// Get the public key from the certificate
//	EVP_PKEY* public_key = X509_get_pubkey(cert);
//	if (!public_key) {
//		std::cerr << "Error extracting public key" << std::endl;
//		X509_free(cert);
//		BIO_free(bio);
//	}
//
//	// Extract the RSA public key
//	if (EVP_PKEY_id(public_key) != EVP_PKEY_RSA) {
//		std::cerr << "Public key is not an RSA key" << std::endl;
//		EVP_PKEY_free(public_key);
//		X509_free(cert);
//		BIO_free(bio);
//	}
//
//	RSA *p_rsa = EVP_PKEY_get1_RSA(public_key);
//
//	const BIGNUM* n, * e;
//	RSA_get0_key(p_rsa, &n, &e, NULL);
//
//	char* modulus_hex = BN_bn2hex(n);
//	char* exponent_hex = BN_bn2hex(e);
//
//	// Print modulus and exponent
//	//std::cout << "Modulus: " << modulus_hex << std::endl;
//   // std::cout << "Exponent: " << exponent_hex << std::endl;
//	EVP_PKEY_free(public_key);
//	X509_free(cert);
//	BIO_free(bio);
//
//	// generate a random premaster secret
//	uint8_t premaster_secret[48];
//	RAND_bytes(premaster_secret, 48);
//	// Insert last 46 bytes of premaster_secret to handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.data()
//	premaster_secret[0] = 0x03;
//	premaster_secret[1] = 0x03;
//	//memcpy(handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.data(),
//				premaster_secret + 2, 46);
//
//	// encrypt the premaster secret using the public key
//	uint8_t encrypted_premaster_secret[256];
//	int rt = RSA_public_encrypt(48, premaster_secret, encrypted_premaster_secret, p_rsa, RSA_PKCS1_PADDING);
////
//	//(handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.data(),
//				encrypted_premaster_secret, 256);
//
//	handshakeProtocol.updateHandshakeProtocol(msg_type);
//
//	serialized_string.append(handshakeProtocol.serialize_handshake_protocol_data(msg_type));
//
//	ChangeCipherSpec changeCipherSpec;
//
//	changeCipherSpec.setChangeCipherSpec();
//
//	serialized_string.append(changeCipherSpec.serialize_change_cipher_spec_data());
//
//	std::cout << "Serialization Test Begins:" << std::endl;
//
//	// Print the bytes
//	std::cout << "The string that is sent is : ";
//	for (size_t i = 0; i < serialized_string.size(); i++) {
//		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(serialized_string[i]);
//	}
//	std::cout << std::endl;
//
//	netlab::L5_socket_impl* ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//	/*NIC nic_client(inet_client, "192.168.1.228", "60:6c:66:62:1c:4f", nullptr, nullptr, true, "ip src 192.168.1.85 or arp ");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	inet_client.connect();
//
//	netlab::tls_socket* ListenSocket = (new netlab::tls_socket(inet_client));
//	sockaddr_in service2;
//	service2.sin_family = AF_INET;
//	service2.sin_addr.s_addr = INADDR_ANY;
//	service2.sin_port = htons(4444);
//
//	ListenSocket->bind((SOCKADDR*)&service2, sizeof(service2));
//	ListenSocket->listen(5);
//
//	netlab::L5_socket* AcceptSocket = nullptr;
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	netlab::tls_socket* accept_tls_scoket = (new netlab::tls_socket(inet_client, AcceptSocket, true));
//	accept_tls_scoket->handshake();
//
//
//	std::string rcv_msg;
//	accept_tls_scoket->recv(rcv_msg, 200, 96, 0);
//
//	cout << rcv_msg << endl;
//
//	std::reverse(rcv_msg.begin(), rcv_msg.end());
//
//
//	accept_tls_scoket->send(rcv_msg, 100, 1, 0);
//
//
//
//	
//	ListenSocket->shutdown(SD_RECEIVE);
//
//
//	cout << "fin" << endl;*/
//}
//
//void tls_playground3()
//{
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//
//	NIC nic_client(inet_client, "192.168.1.225", "60:6c:66:62:1c:4f", nullptr, nullptr, true, "ip src 192.168.1.66 or arp ");
//
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	inet_client.connect();
//	netlab::tls_socket* ListenSocket = (new netlab::tls_socket(inet_client));
//	sockaddr_in service2;
//	service2.sin_family = AF_INET;
//	service2.sin_addr.s_addr = INADDR_ANY;
//	service2.sin_port = htons(4444);
//
//	ListenSocket->bind((SOCKADDR*)&service2, sizeof(service2));
//	ListenSocket->listen(5);
//
//	netlab::L5_socket* AcceptSocket = nullptr;
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	netlab::tls_socket* accept_tls_scoket = (new netlab::tls_socket(inet_client, AcceptSocket, true));
//	accept_tls_scoket->handshake();
//
//
//	std::string rcv_msg;
//	accept_tls_scoket->recv(rcv_msg, 200, 96, 0);
//
//	cout << rcv_msg << endl;
//
//	std::reverse(rcv_msg.begin(), rcv_msg.end());
//
//
//	accept_tls_scoket->send(rcv_msg, 100, 1, 0);
//
//
//
//
//	ListenSocket->shutdown(SD_RECEIVE);
//
//
//	cout << "fin" << endl; 
//}
//
//
//void tls_playground2()
//{
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//
//	NIC nic_client(inet_client, "192.168.1.225", "60:6c:66:62:1c:4f", nullptr, nullptr, true, "ip src 192.168.1.66 or arp ");
//
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//	inet_client.connect();
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_addr("192.168.1.66");
//	clientService.sin_port = htons(433);
//	
//
//	netlab::tls_socket* ConnectSocket = new netlab::tls_socket(inet_client);
//	ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	std::string send_msg("hello world!, this is my first tls implemtation");
//	send_msg.push_back('\n');
//
//
//	ConnectSocket->send(send_msg, 100, 1, 0);
//
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	std::string rcv_msg;
//	ConnectSocket->recv(rcv_msg, 200, 96, 0);
//
//
//	cout << rcv_msg << endl;
//
//	ConnectSocket->shutdown(SD_SEND);
//
//	cout << "fin" << endl;
//}
//
//
//void tls_playground()
//{
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	inet_os inet_server = inet_os();
//
//	NIC nic_client(inet_client,	"10.0.0.15", "bb:bb:bb:bb:bb:bb",nullptr,nullptr,true,"ip src 10.0.0.10 ");
//	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "ip src 10.0.0.15 "); // Declaring a filter to make a cleaner testing.
//
//	L2_impl datalink_client1(inet_server);
//	L2_ARP_impl arp_server(inet_server, 10, 10000);
//	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_server.inetsw(new tcp_reno(inet_server), protosw::SWPROTO_TCP);
//	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_server.domaininit();
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
//	
//	inet_server.connect();
//	inet_client.connect();
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_addr("10.0.0.10");
//	clientService.sin_port = htons(4433);
//;
//
//	netlab::tls_socket* ListenSocket = (new netlab::tls_socket(inet_server));
//	sockaddr_in service2;
//	service2.sin_family = AF_INET;
//	service2.sin_addr.s_addr = INADDR_ANY;
//	service2.sin_port = htons(4433);
//
//	ListenSocket->bind((SOCKADDR*)&service2, sizeof(service2));
//	ListenSocket->listen(5);
//
//	netlab::tls_socket* ConnectSocket = new netlab::tls_socket(inet_client);
//	std::this_thread::sleep_for(std::chrono::seconds(2));
//	std::thread([ConnectSocket, clientService]()
//	{
//			ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//	}).detach();
//	//ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	netlab::L5_socket* AcceptSocket = nullptr;
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	netlab::tls_socket* accept_tls_scoket = (new netlab::tls_socket(inet_server, AcceptSocket, true));
//	accept_tls_scoket->handshake();
//
//	std::string send_msg("hello world!, this is my first tls implemtation");
//	send_msg.push_back('\n');
//
//	 
//	ConnectSocket->send(send_msg, 100,1 ,0);
//
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	std::string rcv_msg;
//	accept_tls_scoket->recv(rcv_msg, 200, 96, 0);
//
//
//	cout << rcv_msg << endl;
//
//	ConnectSocket->shutdown(SD_SEND);
//	ListenSocket->shutdown(SD_RECEIVE);
//	
//	cout << "fin" << endl;
//}
//
//
//void test4(size_t size = 256) 
//{
//	size *= 1000;
//	size *= 1000;
//	/* Declaring the server */
//	//in//et_os inet_server = inet_os();
//
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new tcp_reno(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	//arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	//arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//	//arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//
//	
//
//	/* Spawning both sniffers, 0U means continue forever */
//	//inet_server.connect();
//	inet_client.connect();
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	//netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	//service.sin_family = AF_INET;
//	//service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	//service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	//ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	//ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_addr("192.168.1.239");
//	//inet_pton(AF_INET, "8.8.8.8", &clientService.sin_addr);
//	clientService.sin_port = htons(8888);
//
//
//	WSADATA wsaData;
//	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
//	if (result != 0) {
//		std::cerr << "WSAStartup failed: " << result << std::endl;
//		//return 1;
//	}
//
//	// Create a TCP socket
//	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//	if (server_socket == INVALID_SOCKET) {
//		std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
//		WSACleanup();
//		//return 1;
//	}
//
//	// Set up the server address structure
//	struct sockaddr_in server_addr;
//	server_addr.sin_family = AF_INET;
//	server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
//	server_addr.sin_port = htons(8888);       // Port number
//	
//	// Bind the socket to the server address
//	if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
//		std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
//		closesocket(server_socket);
//		WSACleanup();
//		//return 1;
//	}
//
//	// Listen for incoming connections
//	if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) { // Allow up to SOMAXCONN pending connections in the queue
//		std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
//		closesocket(server_socket);
//		WSACleanup();
//		//return 1;
//	}
//
//	std::cout << "Server listening on port 8888..." << std::endl;
//
//	// Create a thread to handle incoming connections
//	std::thread connectionThread(handleConnections, server_socket, size);
//
//	// Perform other tasks in the main thread
//	// For example, you can wait for user input or do other processing
//
//
//
//
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	//AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::uniform_real_distribution_args(0.05, 0.1), L0_buffer::OUTGOING));
//	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::uniform_real_distribution_args(0.05, 0.1), L0_buffer::OUTGOING));
//
//	std::string send_msg(size, 'T');
//	
//	std::thread([ConnectSocket, send_msg, size]() 
//	{
//		ConnectSocket->send(send_msg, size, 1024);
//		std::cout << "finish shending" << std::endl;
//	}).detach();
//	//ConnectSocket->send(send_msg, size, 512);
//	std::string ret("");
//
//	//int a = AcceptSocket->recv(ret, size,3);
//	//std::cout << a << ret << std::endl;
//		// Join the connection thread to wait for it to finish
//	connectionThread.join();
//
//	// Close server socket
//	closesocket(server_socket);
//	WSACleanup();
//
//	std::cout << ret.size() << std::endl;
////	std::this_thread::sleep_for(std::chrono::seconds(2));
//	//std::cout << "fin?" << std::endl;
//	ConnectSocket->shutdown(SD_SEND);
//	//ListenSocket->shutdown(SD_RECEIVE);
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	//inet_server.stop_fasttimo();
//	//inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(2));
//	//std::this_thread::sleep_for(std::chrono::seconds(10));
//	
//}
//
//void test5() 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//	
//	delete AcceptSocket;
//	delete ConnectSocket;
//	
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void test6()
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	AcceptSocket->shutdown(SD_BOTH);
//	ConnectSocket->shutdown(SD_BOTH);
//	ListenSocket->shutdown(SD_RECEIVE);
//
//	delete ConnectSocket;
//	delete AcceptSocket;
//}
//
//void test7() 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//
//
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect();
//	inet_client.connect();
//	
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::exponential_distribution_args(5)));
//	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(0.5)));
//	inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
//	inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
//
//	std::string send_msg(512*32, 'T');
//	ConnectSocket->send(send_msg);
//	std::this_thread::sleep_for(std::chrono::seconds(30));
//	std::string ret("");
//	AcceptSocket->recv(ret, 512);
//
//
//	std::thread([ConnectSocket, send_msg]()
//	{ 
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//
//		for (size_t i = 0; i < 32; i++)
//		{
//			ConnectSocket->send(send_msg, 512, 512);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//		
//	}).detach();
//
//	std::thread([AcceptSocket, send_msg]()
//	{
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//		std::string ret("");
//		for (size_t i = 0; i < 32; i++)
//		{
//			AcceptSocket->recv(ret, 512);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//	}).join();
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	delete AcceptSocket;
//	delete ConnectSocket;
//
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void test8(bool drop = false) 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (arp and ether src bb:bb:bb:bb:bb:bb) or (arp and ether src cc:cc:cc:cc:cc:cc) or (arp and ether src dd:dd:dd:dd:dd:dd) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client_2 = inet_os();
//	NIC nic_client_2(
//		inet_client_2,
//		"10.0.0.22",
//		"cc:cc:cc:cc:cc:cc",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src cc:cc:cc:cc:cc:cc)");
//
//	L2_impl datalink_client_2(inet_client_2);
//	L2_ARP_impl arp_client_2(inet_client_2, 10, 10000);
//	inet_client_2.inetsw(new L3_impl(inet_client_2, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client_2.inetsw(new L4_TCP_impl(inet_client_2), protosw::SWPROTO_TCP);
//	inet_client_2.inetsw(new L3_impl(inet_client_2, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client_2.domaininit();
//	arp_client_2.insertPermanent(nic_client_2.ip_addr().s_addr, nic_client_2.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client_3 = inet_os();
//	NIC nic_client_3(
//		inet_client_3,
//		"10.0.0.33",
//		"dd:dd:dd:dd:dd:dd",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src dd:dd:dd:dd:dd:dd)");
//
//	L2_impl datalink_client_3(inet_client_3);
//	L2_ARP_impl arp_client_3(inet_client_3, 10, 10000);
//	inet_client_3.inetsw(new L3_impl(inet_client_3, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client_3.inetsw(new L4_TCP_impl(inet_client_3), protosw::SWPROTO_TCP);
//	inet_client_3.inetsw(new L3_impl(inet_client_3, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client_3.domaininit();
//	arp_client_3.insertPermanent(nic_client_3.ip_addr().s_addr, nic_client_3.mac()); // Inserting my address
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//	inet_client_2.connect(0U);
//	inet_client_3.connect(0U);
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket_2(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client_2));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService_2;
//	clientService_2.sin_family = AF_INET;
//	clientService_2.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService_2.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket_2->connect((SOCKADDR *)& clientService_2, sizeof(clientService_2));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket_2 = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket_2 = ListenSocket->accept(nullptr, nullptr);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket_3(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client_3));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService_3;
//	clientService_3.sin_family = AF_INET;
//	clientService_3.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService_3.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket_3->connect((SOCKADDR *)& clientService_3, sizeof(clientService_3));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket_3 = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket_3 = ListenSocket->accept(nullptr, nullptr);
//
//	if (drop)
//	{
//		//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::exponential_distribution_args(1)));
//		inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(1)));
//		inet_client_2.cable()->set_buf(new L0_buffer(inet_client_2, 0.9, L0_buffer::exponential_distribution_args(1)));
//		//inet_client_3.cable()->set_buf(new L0_buffer(inet_client_3, 0.9));
//	}
//
//
//	string recv_msg("");
//	string send_msg;
//
//	send_msg = "B: Hi, I am B!";
//	ConnectSocket->send(send_msg, send_msg.size());
//	AcceptSocket->recv(recv_msg, send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	string welcome_msg = string("A: Hi, I am a simple chat server. I currently hold: ")
//		+ inet_client.nic()->mac().to_string() + ","
//		+ inet_client_2.nic()->mac().to_string() + ", "
//		+ inet_client_3.nic()->mac().to_string() + ". With whom would you like to speak ?";
//
//	AcceptSocket->send(welcome_msg, welcome_msg.size());
//	ConnectSocket->recv(recv_msg = "", welcome_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "B: C"; // C
//
//	ConnectSocket->send(send_msg, send_msg.size());
//	AcceptSocket->recv(recv_msg = "", send_msg.size());
//
//	send_msg = "A: Please send the message dedicated for C.";
//
//	AcceptSocket->send(send_msg, send_msg.size());
//	ConnectSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "B: Hi C, How are you ?"; //"Hi " + keep + ", How are you ?"
//
//	ConnectSocket->send(send_msg, send_msg.size());
//	AcceptSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "C: fine, thank you. what about D? I'll check on him."; // fine, thank you. what about D? I'll check on him.
//
//	ConnectSocket_2->send(send_msg, send_msg.size());
//	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket->send(send_msg, send_msg.size());
//	ConnectSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "B: Ok I won't bug you anymore. Update me on D status."; // Ok I won't bug you anymore. Update me on D status.
//
//	ConnectSocket->send(send_msg, send_msg.size());
//	AcceptSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "C: Hey D, Knock knock.";
//	ConnectSocket_2->send(send_msg, send_msg.size());
//	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_3->send(send_msg, send_msg.size());
//	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "D: Who's there?"; // “Who’s there?”
//
//	ConnectSocket_3->send(send_msg, send_msg.size());
//	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "C: Little old lady."; // Little old lady.
//	ConnectSocket_2->send(send_msg, send_msg.size());
//	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_3->send(send_msg, send_msg.size());
//	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "D: Little old lady who?"; // Little old lad who?
//
//	ConnectSocket_3->send(send_msg, send_msg.size());
//	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "C: I didn't know you could yodel..."; // I didn't know you could yodel...
//	ConnectSocket_2->send(send_msg, send_msg.size());
//	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_3->send(send_msg, send_msg.size());
//	ConnectSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "D: Ha Ha..."; // Ha Ha!
//
//	ConnectSocket_3->send(send_msg, send_msg.size());
//	AcceptSocket_3->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "C: Hey, D still got a sense of humor!"; // Hey, D still got a sence of humor!
//
//	ConnectSocket_2->send(send_msg, send_msg.size());
//	AcceptSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket->send(send_msg, send_msg.size());
//	ConnectSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = "B: If you told him your yodel knock-knock joke, its not considered humor at all...";
//	ConnectSocket->send(send_msg, send_msg.size());
//	AcceptSocket->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//	send_msg = string("A: Incoming message from ") + recv_msg;
//	AcceptSocket_2->send(send_msg, send_msg.size());
//	ConnectSocket_2->recv(recv_msg = "", send_msg.size());
//	inet_server.print_mutex.lock();
//	cout << recv_msg << endl;
//	inet_server.print_mutex.unlock();
//
//
//
//
//
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//	inet_client_2.stop_fasttimo();
//	inet_client_2.stop_slowtimo();
//	inet_client_3.stop_fasttimo();
//	inet_client_3.stop_slowtimo();
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	ConnectSocket->shutdown(SD_BOTH);
//	AcceptSocket->shutdown(SD_BOTH);
//
//	ConnectSocket_2->shutdown(SD_BOTH);
//	AcceptSocket_2->shutdown(SD_BOTH);
//
//	ConnectSocket_3->shutdown(SD_BOTH);
//	AcceptSocket_3->shutdown(SD_BOTH);
//
//	ListenSocket->shutdown(SD_RECEIVE);
//
//	delete ConnectSocket;
//	delete ConnectSocket_2;
//	delete ConnectSocket_3;
//
//	delete AcceptSocket;
//	delete AcceptSocket_2;
//	delete AcceptSocket_3;
//
//}
//
//void test9() { return test8(true); }
//
//void test10() 
//{
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//
//
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect();
//	inet_client.connect();
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::exponential_distribution_args(5)));
//	//inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::exponential_distribution_args(0.5)));
//	inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.5, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
//	inet_server.cable()->set_buf(new L0_buffer(inet_server, 1, L0_buffer::uniform_real_distribution_args(0.5, 5), L0_buffer::OUTGOING));
//
//	std::string send_msg(512, 'T');
//	std::thread([ConnectSocket, send_msg]()
//	{
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//
//		for (size_t i = 0; i < 32; i++)
//		{
//			ConnectSocket->send(send_msg, 512, 512);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//
//	}).detach();
//
//	std::thread([AcceptSocket, send_msg]()
//	{
//		typedef std::chrono::nanoseconds nanoseconds;
//		typedef std::chrono::duration<double> seconds;
//		typedef std::random_device generator;
//		generator gen;
//		std::exponential_distribution<> dist(3);
//		std::string ret("");
//		for (size_t i = 0; i < 32; i++)
//		{
//			AcceptSocket->recv(ret, 512);
//			std::this_thread::sleep_for(std::chrono::duration_cast<nanoseconds>(seconds(dist(gen))));
//		}
//	}).join();
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void test11() {
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//
//
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect();
//	inet_client.connect();
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//
//	std::string send_msg(250*1024, 'T');
//
//	std::thread([ConnectSocket, send_msg]()
//	{
//		ConnectSocket->send(send_msg, send_msg.size(), 512);
//	}).detach();
//	
//	std::this_thread::sleep_for(std::chrono::seconds(180));
//	std::string ret("");
//	AcceptSocket->recv(ret, send_msg.size());
//
//	inet_client.stop_fasttimo();
//	inet_client.stop_slowtimo();
//
//	inet_server.stop_fasttimo();
//	inet_server.stop_slowtimo();
//	std::this_thread::sleep_for(std::chrono::seconds(1));
//
//	ListenSocket->shutdown(SD_RECEIVE);
//}
//
//void handler(int request) 
//{
//	int packet_size(0), num(0);
//	char remember('Y');
//	switch (request)
//	{
//	case 1:
//		return test1();
//		break;
//	case 2:
//		return test2();
//		break;
//	case 3:
//		std::cout << "Please insert the wanted packet size or 0 to use the default (32):" << std::endl;
//		std::cin >> packet_size;
//		if (packet_size == 0)
//			packet_size = 32;
//		std::cout << "Please insert the wanted number of times to send the packet or 0 to use the default (5):" << std::endl;
//		std::cin >> num;
//		if (num == 0)
//			num = 5;
//		return test3(packet_size, num);
//		break;
//	case 4:
//		/*std::cout << "Did you remember to define the mac buffer size in L5.h [Y/N] ?" << std::endl;
//		std::cin >> remember;
//		if (remember == 'N')
//		{
//			std::cout << "Then change it and try again, closing program." << std::endl;
//			std::this_thread::sleep_for(std::chrono::seconds(3));
//			return;
//		}*/
//		std::cout << "Please insert the wanted packet size in MB, or 0 to use the default (256):" << std::endl;
//		std::cin >> packet_size;
//		if (packet_size > 256)
//		{
//			std::cout << "Max size is 256, using 256MB as packet size." << std::endl;
//			packet_size = 256;
//		}
//		return test4(packet_size);
//		break;
//	case 5:
//		return test5();
//		break;
//	case 6:
//		return test6();
//		break;
//	case 7:
//		return test7();
//		break;
//	case 8:
//		return test8();
//		break;
//	case 9:
//		return test9();
//		break;
//	case 10:
//		return test10();
//		break;
//	default:
//		return;
//		break;
//	}
//}
//
//void main() 
//{
//
//	std::cout << "Hello and Welcome to the test Unit!" << std::endl <<
//		"Please insert the wanted test number:" << std::endl <<
//		"[1] Resolving an IP address Using ARP" << std::endl <<
//		"[2] Opening a TCP Connection Using the TCP 3-way Handshake" << std::endl <<
//		"[3] Sending a Small Packet Using TCP" << std::endl <<
//		"[4] Sending a Large Packet Using TCP" << std::endl <<
//		"[5] Closing a TCP Connection" << std::endl <<
//		"[6] Shutting Down a TCP Connection" << std::endl <<
//		"[7] Combined Test: Unreliable and Delayed Channel" << std::endl <<
//		"[8] Application Use Case" << std::endl <<
//		"[9] Application Use Case (with drop)" << std::endl <<
//		"[10] Cwnd Fall Test" << std::endl;
//
//	cout << "test1" << endl;
//	tls_playground();
//	cout << "test2" << endl;
//	tls_playground2();
//	cout << "test3" << endl;
//	//tls_playground3();
//	return;
//
//	int request(4);
//	//std::cin >> request;
//	while (request)
//	{
//
//		handler(request);
//		std::cout << "Please insert another test number, or 0 to terminate." << std::endl;
//		std::cin >> request;
//	}
//	return;
//
//
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//
//	/* Declaring the server */
//	inet_os inet_server = inet_os();
//
//	/* Declaring the server's NIC */
//	NIC nic_server(
//		inet_server,			// Binding this NIC to our server
//		"10.0.0.10",			// Giving it an IP address
//		"aa:aa:aa:aa:aa:aa",	// Givinig it a MAC address
//		nullptr,				// Using my real machine default gateway address.
//		nullptr,				// Using my real machine broadcast address.
//		true,					// Setting the NIC to be in promisc mode
//		"(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port 8888 and not ether src aa:aa:aa:aa:aa:aa)"); // Declaring a filter to make a cleaner testing.
//	
//	/* Declaring the server's datalink using my L2_impl */
//	L2_impl datalink_server(inet_server);
//	
//	/* Declaring the server's arp using my L2_ARP_impl */
//	L2_ARP_impl arp_server(
//		inet_server,	// Binding this NIC to our server
//		10,			// arp_maxtries parameter
//		10000);		// arpt_down parameter
//
//	/* Declaring protocols is a bit different: */
//	inet_server.inetsw(
//		new L3_impl(inet_server, 0, 0, 0),	// A default IP layer is defined, using my L3_impl, as in a real BSD system 
//		protosw::SWPROTO_IP);				// I place the layer in the appropriate place, though any place should do. 
//	inet_server.inetsw(
//		new L4_TCP_impl(inet_server),		// Defining the TCP Layer using my L4_TCP_impl
//		protosw::SWPROTO_TCP);				// Placing it in the appropriate place.
//	inet_server.inetsw(
//		new L3_impl(						// The actual IP layer we will use.
//		inet_server,						// Binding this NIC to our server
//		SOCK_RAW,							// The protocol type
//		IPPROTO_RAW,						// The protocol
//		protosw::PR_ATOMIC | protosw::PR_ADDR),	// Protocol flags
//		protosw::SWPROTO_IP_RAW);			// Placing it in the appropriate place.
//	
//	inet_server.domaininit();	// This calls each pr_init() for each defined protocol.
//	
//	arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // Inserting my address
//	
//	/* Client is declared similarly: */
//	inet_os inet_client = inet_os();
//	NIC nic_client(
//		inet_client,
//		"10.0.0.15",
//		"bb:bb:bb:bb:bb:bb",
//		nullptr,
//		nullptr,
//		true,
//		"(arp and ether src aa:aa:aa:aa:aa:aa) or (tcp port 8888 and not ether src bb:bb:bb:bb:bb:bb)");
//	
//	L2_impl datalink_client(inet_client);
//	L2_ARP_impl arp_client(inet_client, 10, 10000);
//	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
//	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
//	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
//	inet_client.domaininit();
//	arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // My
//
//	arp_client.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac()); // server
//	arp_server.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac()); // client
//
//	/* Spawning both sniffers, 0U means continue forever */
//	inet_server.connect(0U);
//	inet_client.connect(0U);
//
//
//	// The socket address to be passed to bind
//	sockaddr_in service;
//	
//	//----------------------
//	// Create a SOCKET for listening for 
//	// incoming connection requests
//	netlab::L5_socket_impl *ListenSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
//	
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port for the socket that is being bound.
//	service.sin_family = AF_INET;
//	service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	service.sin_port = htons(8888);
//
//	//----------------------
//	// Bind the socket.
//	ListenSocket->bind((SOCKADDR *)&service, sizeof(service));
//
//	//----------------------
//	// Listen for incoming connection requests 
//	// on the created socket
//	// 
//	ListenSocket->listen(5);
//
//	//----------------------
//	// Create a SOCKET for connecting to server
//	netlab::L5_socket_impl *ConnectSocket(new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));
//
//	//----------------------
//	// The sockaddr_in structure specifies the address family,
//	// IP address, and port of the server to be connected to.
//	sockaddr_in clientService;
//	clientService.sin_family = AF_INET;
//	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
//	clientService.sin_port = htons(8888);
//
//	//----------------------
//	// Connect to server.
//	ConnectSocket->connect((SOCKADDR *)& clientService, sizeof(clientService));
//
//	//----------------------
//	// Create a SOCKET for accepting incoming requests.
//	netlab::L5_socket_impl *AcceptSocket = nullptr;
//
//	//----------------------
//	// Accept the connection.
//	AcceptSocket = ListenSocket->accept(nullptr, nullptr);
//	
//	
//
//
//
//	std::string re("");
//	ConnectSocket->shutdown(SD_SEND);
//	//std::this_thread::sleep_for(std::chrono::seconds(5));
//	try 
//	{
//		ConnectSocket->send(string(1024, 'T'));
//	}
//	catch (runtime_error &e)
//	{
//		cout << e.what() << endl;
//	}
//	AcceptSocket->shutdown(SD_RECEIVE);
//	//std::this_thread::sleep_for(std::chrono::seconds(5));
//	
//	try
//	{
//		AcceptSocket->recv(re, 1024);
//	}
//	catch (runtime_error &e)
//	{
//		cout << e.what() << endl;
//	}
//	
//	AcceptSocket->shutdown(SD_SEND);
//	//std::this_thread::sleep_for(std::chrono::seconds(5));
//	try
//	{
//		AcceptSocket->send(string(1024, 'T'));
//	}
//	catch (runtime_error &e)
//	{
//		cout << e.what() << endl;
//	}
//	ConnectSocket->shutdown(SD_RECEIVE);
//	//std::this_thread::sleep_for(std::chrono::seconds(5));
//	try
//	{
//		ConnectSocket->recv(re, 1024);
//	}
//	catch (runtime_error &e)
//	{
//		cout << e.what() << endl;
//	}
//
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	AcceptSocket->shutdown(SD_SEND);	
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	
//
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	ConnectSocket->shutdown(SD_RECEIVE);
//	std::this_thread::sleep_for(std::chrono::seconds(5));
//	//ConnectSocket->shutdown(SD_RECEIVE);
//	delete AcceptSocket;
//	
//	std::this_thread::sleep_for(std::chrono::seconds(60));
//	ConnectSocket->shutdown(SD_BOTH);
//	AcceptSocket->shutdown(SD_BOTH);
//
//	delete AcceptSocket;
//	delete ConnectSocket;
//
//	int str_size(256*1024);
//	std::string send_str(str_size, 'T');
//	std::string ret("");
//
//	ConnectSocket->send(send_str);
//
//	for (size_t i = 0; i < 30; i++)
//	{
//		std::this_thread::sleep_for(std::chrono::seconds(10));
//		inet_client.print_mutex.lock();
//		std::this_thread::sleep_for(std::chrono::seconds(1));
//		inet_client.print_mutex.unlock();
//		inet_server.print_mutex.lock();
//		std::this_thread::sleep_for(std::chrono::seconds(1));
//		inet_server.print_mutex.unlock();
//
//	}
//
//	AcceptSocket->recv(ret, str_size);
//	
//	std::this_thread::sleep_for(std::chrono::seconds(60));
//
//	int iResult = 0;            // used to return function results
//	
//	//int server;
//	//std::cin >> server;
//	//if (server)
//	//{
//
//		
//
//
//
//
//
//
//
//	/*}
//	else
//	{*/
//
//
//
//	//}
//	
//	
//	//send_syn(IPv4Address("172.16.65.131"), 8888, datalink);
//	//Sleep(2000);
//	//send_ack(IPv4Address("172.16.65.131"), 8888, datalink);
//
//
//
//	int retFlag(0);
//	
////	int stop;
//	//Sleep(3000);
//	
//	std::thread([ConnectSocket, send_str]() { ConnectSocket->send(send_str, 1024); }).detach();
//	std::this_thread::sleep_for(std::chrono::seconds(20));
//
//	std::thread([AcceptSocket, str_size]()
//	{ 
//		std::string ret("");
//		AcceptSocket->recv(ret, str_size, 1);
//		std::cout << "received buffer of size: " << std::to_string(ret.size()) << std::endl;
//	}).detach();
//	std::this_thread::sleep_for(std::chrono::seconds(150));
//	AcceptSocket->recv(ret, str_size);
//	std::cout << "received buffer of size: " << std::to_string(ret.size()) << std::endl;
//	
//	//ConnectSocket->sosend(send_str);
//	Sleep(5000);
//	Sleep(15000);
//	ConnectSocket->shutdown(SD_SEND);
//	Sleep(5000);
//	AcceptSocket->shutdown(SD_RECEIVE);
//	Sleep(15000);
//	pthread_mutex_t _mutex;
//	pthread_mutex_init(&_mutex, NULL);
//	pthread_mutex_lock(&_mutex);
//	pthread_mutex_lock(&_mutex);
//	delete AcceptSocket;
//	Sleep(5000);
//	delete ListenSocket;
//	//ListenSocket->shutdown(SD_RECEIVE);
//	
//	//AcceptSocket->shutdown(SD_RECEIVE);
//
//	// shutdown the connection since no more data will be sent
//	//ConnectSocket->shutdown(2);
//	//delete ConnectSocket;
//	int f(0);
//	// Receive until the peer closes the connection
//	do {
//		ret = "";
//		ConnectSocket->recv(ret, 1024, f, 1024);
//		if (ret != "")
//			std::cout << "Bytes received: " << ret.size() << " = " << ret << endl;
//
//	} while (ret != "");
//
//
//	// close the socket
//	delete ConnectSocket;
//	
//	Sleep(1000);
//	//ConnectSocket->soreceive_stream(ret, send_str.size(), retFlag);
//	//std::cin >> stop;
//	//AcceptSocket->sosend(nullptr, send_str, nullptr, 0);
//	//std::cin >> stop;
//	////Sleep(5000);
//	//ConnectSocket->soreceive_stream(ret, send_str.size(), retFlag);
//	//std::cin >> stop;
//
//	return;
//
//	ConnectSocket->shutdown(2);
//	Sleep(5000);
//	delete ConnectSocket;
//	Sleep(5000);
//	delete AcceptSocket;
//	Sleep(5000);
//
//	//pthread_mutex_t _mutex;
//	//pthread_mutex_init(&_mutex, NULL);
//	//pthread_mutex_lock(&_mutex);
//	//pthread_mutex_lock(&_mutex);
//	
//	/* L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.*/
//	//sendToL3(toSend, icmp_pdu.size(), resolvedSrcIP.to_string(), resolvedDestIP.to_string());
//	//Transport->sendToL4((byte *)test, testLen, dstIP, "");
//	byte* readData = new byte[1500];
//	
//
//	//Transport->readFromL4(readData, 1500);
//	//inet.print_lock();
//	//cout << string((char*)readData, testLen) << endl;
//	//inet.print_unlock();
//
//
//	int argc = 4;
//	//char *argv[3] = { "", "172.16.65.131", "8888"};
//	char *argv[4] = { "", "10.0.0.11", "9998", "9999" };
//	//if (argc < 3 && cout << "Usage: " << *argv << " <IPADDR> <port1> [port2] [port3]\n")
//	//	return 1;
//	try {
//		//scan(argc, argv, datalink);
//	}
//	catch (std::runtime_error &ex) {
//		cout << "Error - " << ex.what() << endl;
//	}
//
//	delete ListenSocket;
//	return;
//}
//
//
//
