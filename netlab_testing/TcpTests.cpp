#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <chrono>

#include "pch.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "../netlab/L5/tls_socket.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include "BaseTest.hpp"

using namespace std;

enum tcp_flavor
{
	TCP_BASE,
	TCP_TAHOE,
	TCP_RENO
};


typedef netlab::HWAddress<> mac_addr;

void handleConnections(SOCKET server_socket, size_t expected_bytes, std::string* ret_msg) {
	struct sockaddr_in client_addr;
	int client_addr_len = sizeof(client_addr);
	int total = 0;

	// Receive data from the client
	char* buffer = new char[expected_bytes];
	memset(buffer, 0, expected_bytes); // Clear the buffer (optional

	while (true) {
		// Accept incoming connections
		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
			return;
		}

		std::cout << "Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;

		int bytes_received;
		while ((bytes_received = recv(client_socket, buffer + total, sizeof(buffer), 0)) > 0) {
			total += bytes_received;
			if (total >= expected_bytes) { break; }
		}

		// Check if recv failed
		if (bytes_received == SOCKET_ERROR) {
			std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
		}

		// Close client socket
		closesocket(client_socket);

		break;
	}


	string str_to_copy(buffer);
	str_to_copy.resize(total);
	*ret_msg = str_to_copy;
	delete[] buffer;

	ASSERT_EQ(total, expected_bytes);

	return;
}


class TCP_Tests : public test_base {

protected:

	/* Declaring the ip address from the current machine */
	std::string ip_address;
	
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

	TCP_Tests() : test_base("ip src 10.0.0.10" , "ip src 10.0.0.15")
	{
		inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
		inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	}

 
	void set_tcp(inet_os& os ,tcp_flavor tcp_type)
	{
		switch (tcp_type)
		{
		case TCP_BASE:
			os.inetsw(new L4_TCP_impl(os), protosw::SWPROTO_TCP);
			break;
		case TCP_TAHOE:
			os.inetsw(new tcp_tahoe(os), protosw::SWPROTO_TCP);
			break;
		case TCP_RENO:
			os.inetsw(new tcp_tahoe(os), protosw::SWPROTO_TCP);
			break;

		default:
			break;
		}

		os.domaininit();
	}

	
	// reciver socket is OS / our impl
	// sender socket is our implementation
	virtual void test_sender()
	{
		ConnectSocket = new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client);

		sockaddr_in client_service;
		client_service.sin_family = AF_INET;
		client_service.sin_addr.s_addr = inet_addr(my_ip.c_str());
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
		bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));

		// Listen for incoming connections
		listen(server_socket, SOMAXCONN);

		std::cout << "Server listening on port 8888..." << std::endl;

		std::string send_msg(1000 * 50, 'T');
		std::string ret_msg_from_os;
		ret_msg_from_os.resize(send_msg.size());
		size_t size = send_msg.size();

		// Create a thread to handle incoming connections
		std::thread connectionThread(handleConnections, server_socket, size, &ret_msg_from_os);

		ConnectSocket->connect((SOCKADDR*)&client_service, sizeof(client_service));
		netlab::L5_socket_impl* client_socket = ConnectSocket;
		std::thread([client_socket, send_msg, size]()
		{
			client_socket->send(send_msg, size, 1024);
		}).detach();

		connectionThread.join();


		netlab::L5_socket_impl* ListenSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));
		sockaddr_in service2;
		service2.sin_family = AF_INET;
		service2.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		service2.sin_port = htons(8888);

		ListenSocket->bind((SOCKADDR*)&service2, sizeof(service2));
		ListenSocket->listen(5);

		ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		clientService.sin_port = htons(8888);

		ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));

		netlab::L5_socket_impl* AcceptSocket = nullptr;

		AcceptSocket = ListenSocket->accept(nullptr, nullptr);

		netlab::L5_socket_impl* connectSocket = this->ConnectSocket;
		std::thread([connectSocket, send_msg, size]()
		{
			connectSocket->send(send_msg, size, 1024);
		}).detach();

		std::string ret("");
		int a = AcceptSocket->recv(ret, size, 3);

		ASSERT_EQ(ret_msg_from_os, send_msg);
		ASSERT_EQ(ret_msg_from_os, ret);

		ConnectSocket->shutdown(SD_SEND);
		ListenSocket->shutdown(SD_RECEIVE);

		// Close server socket
		closesocket(server_socket);
		WSACleanup();

	}

	// reciver socket is our implementation
	// sender socket is OS / our impl
	virtual void test_reciver()
	{
		// sokcet for incoming connection requests
		ListenSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

		// The sockaddr_in structure specifies the address family, IP address, and port for the socket that is being bound.
		service.sin_family = AF_INET;
		service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		service.sin_port = htons(8888);

		// Bind & listerthe socket.
		ListenSocket->bind((SOCKADDR*)&service, sizeof(service));
		ListenSocket->listen(5);

		// Create a SOCKET for connecting to server
		WSADATA wsaData;
		int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		SOCKET client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		// Set up the server address structure
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(8888); // Port number
		server_addr.sin_addr.S_un.S_addr = inet_server.nic()->ip_addr().s_addr;

		// Connect to the server
		if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
			std::cerr << "Connect failed: " << WSAGetLastError() << std::endl;
			closesocket(client_socket);
			WSACleanup();
		}

		std::cout << "Connected to server at 10.0.0.10:8888" << std::endl;

		// Accept the connection.
		AcceptSocket = ListenSocket->accept(nullptr, nullptr);

		// Send data to the server
		std::string send_msg(50 * 1000, 'T');
		size_t size = send_msg.size();
		int bytes_sent = send(client_socket, send_msg.c_str(), size, 0);
		if (bytes_sent == SOCKET_ERROR) {
			std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
		}

		std::string ret = "";
		int byte_recived_from_os = AcceptSocket->recv(ret, size, 3);

		// varify the retrive msg againt the original
		ASSERT_EQ(ret, send_msg);
		ASSERT_EQ(ret.size(), size);
		ASSERT_EQ(byte_recived_from_os, size);

		// Close socket
		closesocket(client_socket);
		WSACleanup();

		ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		clientService.sin_port = htons(8888);

		ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));

		AcceptSocket = ListenSocket->accept(nullptr, nullptr);

		netlab::L5_socket_impl* connectSocket = this->ConnectSocket;
		std::thread([connectSocket, send_msg, size]()
		{
			connectSocket->send(send_msg, size, 1024);
		}).detach();

		std::string ret2 = "";
		int byte_recived = AcceptSocket->recv(ret2, size, 3);


		ConnectSocket->shutdown(SD_SEND);
		ListenSocket->shutdown(SD_RECEIVE);

		ASSERT_EQ(byte_recived, size);
		ASSERT_EQ(ret2, send_msg);
		ASSERT_EQ(ret, ret2); 
	}

	virtual void test_big_packet()
	{

		ListenSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server));

		//----------------------
		// The sockaddr_in structure specifies the address family,
		// IP address, and port for the socket that is being bound.
		service.sin_family = AF_INET;
		service.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		service.sin_port = htons(8888);

		//// Bind the socket and listen.
		ListenSocket->bind((SOCKADDR*)&service, sizeof(service));
		ListenSocket->listen(5);

		//// Create a SOCKET for connecting to server
		ConnectSocket = (new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client));

		// The sockaddr_in structure specifies the address family, IP address, and port of the server to be connected to.
		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
		clientService.sin_port = htons(8888);

		// Connect to server.
		ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));

		// Accept the connection.
		AcceptSocket = ListenSocket->accept(nullptr, nullptr);


		//inet_server.cable()->set_buf(new L0_buffer(inet_server, 0.75, L0_buffer::uniform_real_distribution_args(0, 0.001), L0_buffer::OUTGOING));
		//inet_client.cable()->set_buf(new L0_buffer(inet_client, 0.9, L0_buffer::uniform_real_distribution_args(0, 1), L0_buffer::INCOMING));

		std::string send_msg(500 * 1024, 'T');
		size_t size = send_msg.size();

		netlab::L5_socket_impl* connectSocket = this->ConnectSocket;
		std::thread([connectSocket, send_msg, size]()
		{
			connectSocket->send(send_msg, size, 1024);
		}).detach();


		std::string ret("");

		int byte_recived = AcceptSocket->recv(ret, size, 3);


		ConnectSocket->shutdown(SD_SEND);
		ListenSocket->shutdown(SD_RECEIVE);

		ASSERT_EQ(byte_recived, size);
		ASSERT_EQ(ret, send_msg);
	}

	void run_all_test(tcp_flavor tcp_type) {


		set_tcp(inet_client, tcp_type);
		set_tcp(inet_server, tcp_type);

		std::cout << "start recive test" << std::endl;
		  
		test_reciver();

		set_tcp(inet_client, tcp_type);
		set_tcp(inet_server, tcp_type);

		std::cout << "pass recive test" << std::endl;
		std::cout << "start sender test" << std::endl;

		test_sender();

		set_tcp(inet_client, tcp_type);
		set_tcp(inet_server, tcp_type);

		std::cout << "pass sender test" << std::endl;
		std::cout << "start big msg test" << std::endl;

		test_big_packet();

		std::cout << "pass big msg test" << std::endl;
	}

};

void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}



SSL_CTX* create_context() {
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	method = TLS_server_method(); // Using TLS_server_method for TLS 1.2
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set options to disable all extensions and only allow TLS 1.2
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET | SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_ENCRYPT_THEN_MAC | SSL_OP_NO_TICKET) ;




	return ctx;
}


void configure_context(SSL_CTX* ctx) {
	SSL_CTX_use_certificate_file(ctx, "C:/Program Files/OpenSSL-Win64/server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "C:/Program Files/OpenSSL-Win64/server.key", SSL_FILETYPE_PEM);
}

class TLS_test : public TCP_Tests {

public:
	void test_sender() override
	{/*
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);

		int sockfd, newsockfd;
		struct sockaddr_in addr;
		int addr_len = sizeof(addr);

		init_openssl();
		SSL_CTX* ctx = create_context();

		configure_context(ctx);



		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			perror("Unable to create socket");
			exit(EXIT_FAILURE);
		}

		addr.sin_family = AF_INET;
		addr.sin_port = htons(4433);
		addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
			perror("Unable to bind");
			exit(EXIT_FAILURE);
		}

		if (listen(sockfd, 1) < 0) {
			perror("Unable to listen");
			exit(EXIT_FAILURE);
		}*/

		


		sockaddr_in clientService;
		clientService.sin_family = AF_INET;
		clientService.sin_addr.s_addr = inet_addr("192.168.1.73");
		clientService.sin_port = htons(4433);

		netlab::tls_socket* ConnectSocket = new netlab::tls_socket(inet_client);
		ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));


		std::cout << "AA" << std::endl;

	/*	std::thread([ConnectSocket, clientService]()
		{
				ConnectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
		}).detach();
*/

		//std::this_thread::sleep_for(std::chrono::seconds(1));
		//newsockfd = accept(sockfd, (struct sockaddr*)&addr, &addr_len);
		//if (newsockfd < 0) {
		//	perror("Unable to accept");
		//	exit(EXIT_FAILURE);
		//}

		//SSL* ssl = SSL_new(ctx);
		//SSL_set_fd(ssl, newsockfd);

		//if (SSL_accept(ssl) <= 0) {
		//	ERR_print_errors_fp(stderr);
		//}
		//
		//char buffer[1024] = { 0 };
		//int bytes = SSL_read(ssl, buffer, sizeof(buffer));







		//SSL_shutdown(ssl);
		//SSL_free(ssl);
		//closesocket(newsockfd);
		//
	}

};

TEST_F(TCP_Tests, test_reno)
{
	run_all_test(TCP_RENO);
}


//TEST_F(TCP_Tests, test_tahoe)
//{
//	run_all_test(TCP_TAHOE);
//}
//
//TEST_F(TCP_Tests, test_base)
//{
//	run_all_test(TCP_BASE);
//}
//
//
//TEST_F(TLS_test, tls_test)
//{
//	set_tcp(inet_client,TCP_RENO);
//	set_tcp(inet_server, TCP_RENO);
//	test_sender();
//}