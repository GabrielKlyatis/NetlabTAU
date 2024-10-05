#include "pch.h"
#include "../netlab/L5/HTTP/HTTPServer_Impl.hpp"
#include "../netlab/L5/HTTP/HTTPClient_Impl.hpp"


#pragma comment(lib, "ws2_32.lib")

#include "BaseTest.hpp"

using namespace netlab;

class HTTP_Tests : public test_base {
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

	netlab::HTTPServer_Impl* http_server;
	netlab::HTTPClient_Impl* http_client;

	HTTP_Tests() : test_base("", "(arp and ether src bb:bb:bb:bb:bb:bb) or (tcp port (8888 or 4433) and not ether src aa:aa:aa:aa:aa:aa)")
	{

		inet_server.inetsw(new L4_TCP_impl(inet_server), protosw::SWPROTO_TCP);
		inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);

		inet_server.domaininit();
		inet_client.domaininit();

		arp_server.insertPermanent(nic_server.ip_addr().s_addr, nic_server.mac());
		arp_client.insertPermanent(nic_client.ip_addr().s_addr, nic_client.mac());
	}

	void SetUp() override {

		test_base::SetUp();

		http_server = new HTTPServer_Impl();
		http_client = new HTTPClient_Impl();
	}

	void TearDown() override {

		std::this_thread::sleep_for(std::chrono::seconds(2));

		inet_client.stop_fasttimo();
		inet_client.stop_slowtimo();

		inet_server.stop_fasttimo();
		inet_server.stop_slowtimo();

		std::this_thread::sleep_for(std::chrono::seconds(5));

		/*delete http_server;
		delete http_client;*/
	}

	void set_HTTP_variant(HTTPProtocol http_protocol) {
		http_server->set_HTTP_procotol(http_protocol, inet_server);
		http_client->set_HTTP_procotol(http_protocol, inet_client);
	}
	
	void connect_to_server() {
		http_server->listen_for_connection();
		http_client->connect_to_server(inet_server, http_server);
		http_server->accept_connection(inet_server);
	}
};

TEST_F(HTTP_Tests, HTTP_GET_inet_os) {

	std::cout << "HTTP GET inet_os Test" << std::endl;
	set_HTTP_variant(HTTPProtocol::HTTP);
	connect_to_server();

	std::string get_request = "GET /msg.txt?query=example&sort=asc&page=2 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";

	std::string get_request_uri = "/msg.txt?query=example&sort=asc&page=2";
	std::string get_request_version = "HTTP/1.1";
	HTTPHeaders get_headers = {
		{"Host", "www.google.com"},
		{"Connection", "close"},
		{"Content-Length", "0"}
	};
	QueryParams get_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};
	
	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params);
	ASSERT_EQ(getRequestResult, RESULT_SUCCESS);

	std::string received_request;

	http_server->client_socket->recv(received_request, 131, 0, 0);
	//ASSERT_EQ(received_request, get_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	//ASSERT_EQ(HTTP_request.to_string(), get_request);

	int getResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(getResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, 151, 0, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP GET inet_os Test Passed" << std::endl;
}

TEST_F(HTTP_Tests, HTTP_POST_inet_os) {

	std::cout << "HTTP POST inet_os Test" << std::endl;

	set_HTTP_variant(HTTPProtocol::HTTP);
	connect_to_server();

	std::string post_request = "POST /search?query=example&sort=asc HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\nparam1=value1&param2=value2&query=anotherExample&sort=desc&param3=value3&param4=value4";

	std::string post_request_uri = "/search?query=example&sort=asc";
	std::string post_request_version = "HTTP/1.1";
	std::string post_body = "Hello";
	HTTPHeaders post_headers = {
		{"Host", "www.google.com"},
		{"Connection", "close"},
		{"Content-Length", std::to_string(post_body.size())}
	};
	QueryParams post_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};
	QueryParams post_body_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};

	int postRequestResult = http_client->post(post_request_uri, post_request_version, post_headers, post_params, post_body, post_body_params);
	ASSERT_EQ(postRequestResult, RESULT_SUCCESS);

	std::string received_request;

	http_server->client_socket->recv(received_request, 129, 0, 0);
	//ASSERT_EQ(received_request, post_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	//ASSERT_EQ(HTTP_request.to_string(), post_request);

	int postResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(postResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, 141, 0, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP POST inet_os Test Passed" << std::endl;
}

TEST_F(HTTP_Tests, HTTPS_GET_inet_os) {

	std::cout << "HTTPS GET inet_os Test" << std::endl;
	set_HTTP_variant(HTTPProtocol::HTTPS);
	connect_to_server();

	std::string get_request = "GET /msg.txt?query=example&sort=asc&page=2 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";

	std::string get_request_uri = "/msg.txt?query=example&sort=asc&page=2";
	std::string get_request_version = "HTTP/1.1";
	HTTPHeaders get_headers = {
		{"Host", "www.google.com"},
		{"Connection", "close"},
		{"Content-Length", "0"}
	};
	QueryParams get_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};

	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params);
	ASSERT_EQ(getRequestResult, RESULT_SUCCESS);

	std::string received_request;

	http_server->client_socket->recv(received_request, 200, 1, 0); 
	//ASSERT_EQ(received_request, get_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	//ASSERT_EQ(HTTP_request.to_string(), get_request);

	int getResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(getResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, 200, 1, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP GET inet_os Test Passed" << std::endl;
}