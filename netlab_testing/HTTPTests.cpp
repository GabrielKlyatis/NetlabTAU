#include "pch.h"
#include "../netlab/L5/HTTP/HTTPServer_Impl.hpp"
#include "../netlab/L5/HTTP/HTTPClient_Impl.hpp"


#pragma comment(lib, "ws2_32.lib")

#include "BaseTest.hpp"

using namespace netlab;

/************************************************************************/
/*                        Utility Functions                             */
/************************************************************************/

std::string create_query_string(QueryParams& params) {
	std::string query_string = "?";
	bool first = true;

	for (const auto& param : params) {
		if (!first) {
			query_string += "&";
		}
		query_string += param.first + "=" + param.second;
		first = false;
	}

	return query_string;
}

std::string create_headers_string(HTTPHeaders& headers) {
    std::string headers_string;
    std::vector<std::string> default_request_headers_order = {"Host" ,"User-Agent", "Connection", "Content-Type", "Content-Length"};

    for (const auto& header_name : default_request_headers_order) {
        auto it = headers.find(header_name);
        if (it != headers.end()) {
            std::string header_value = it->second;
            headers_string += header_name + ": " + header_value + "\r\n";
        }
    }

    for (const auto& header : headers) {
        if (std::find(default_request_headers_order.begin(), default_request_headers_order.end(), header.first) == default_request_headers_order.end()) {
            std::string header_value = header.second;
            headers_string += header.first + ": " + header_value + "\r\n";
        }
    }

    return headers_string;
}

/************************************************************************/

/************************************************************************/
/*								HTTP Tests                              */
/************************************************************************/

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

	std::string get_request_method = "GET";
	std::string get_request_uri = "/msg.txt";
	std::string get_request_version = "HTTP/1.1";

	HTTPHeaders get_headers = {
		{"Host", "www.google.com"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type", "text/plain"},
	};

	QueryParams get_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};

	// Create the query string
	std::string get_request = get_request_method + " " + get_request_uri + create_query_string(get_params) + " " + 
		get_request_version + "\r\n" + create_headers_string(get_headers) + "\r\n";
	
	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params); // Send the GET request
	ASSERT_EQ(getRequestResult, RESULT_SUCCESS);

	std::string received_request;
	int request_size = get_request.size();

	http_server->client_socket->recv(received_request, request_size, 0, 0);
	ASSERT_EQ(received_request, get_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);

	int getResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(getResponseResult, RESULT_SUCCESS);

	std::string received_response;
	
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP GET inet_os Test Passed" << std::endl;
}

TEST_F(HTTP_Tests, HTTP_POST_1_inet_os) {

	std::cout << "HTTP POST 1 inet_os Test" << std::endl;

	set_HTTP_variant(HTTPProtocol::HTTP);
	connect_to_server();

	std::string post_request_method = "POST";
	std::string post_request_uri = "/example"; // Full Request URI = Request path + Query string
	std::string post_request_version = "HTTP/1.1";

	QueryParams post_params = {
	{"param1", "value1"},
	{"param2", "value2"},
	{"query", "anotherExample"},
	{"sort", "desc"},
	{"param3", "value3"},
	{"param4", "value4"}
	};

	// Body params will be serialized as URL-encoded
	QueryParams post_body_params = {
		{"body_param1", "body_value1"},
		{"body_param2", "body_value2"},
		{"body_query", "body_anotherExample"},
		{"body_sort", "body_desc"},
		{"body_param3", "body_value3"},
		{"body_param4", "body_value4"}
	};

	// Serialize the body
	std::string post_body = serialize_body(post_body_params, "application/x-www-form-urlencoded");

	// Headers
	HTTPHeaders post_headers = {
		{"Host", "www.example.com"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"Content-Length", std::to_string(post_body.size())}
	};

	// Create the full request string
	std::string post_request = post_request_method + " " + post_request_uri + create_query_string(post_params) + " " + post_request_version + "\r\n";
	post_request += create_headers_string(post_headers) + "\r\n"; // Add headers
	post_request += post_body; // Add serialized body

	int postRequestResult = http_client->post(post_request_uri, post_request_version, post_headers, post_params, post_body, post_body_params);
	ASSERT_EQ(postRequestResult, RESULT_SUCCESS);

	std::string received_request;
	int request_size = post_request.size();

	http_server->client_socket->recv(received_request, request_size, 0, 0);
	ASSERT_EQ(received_request, post_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	ASSERT_EQ(HTTP_request.to_string(), post_request);

	int postResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(postResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP POST inet_os Test Passed" << std::endl;
}

TEST_F(HTTP_Tests, HTTP_POST_2_inet_os) {

	std::cout << "HTTP POST 2 inet_os Test" << std::endl;

	set_HTTP_variant(HTTPProtocol::HTTP);
	connect_to_server();

	std::string post_request_method = "POST";
	std::string post_request_uri = "/example"; // Full Request URI = Request path + Query String
	std::string post_request_version = "HTTP/1.1";

	std::string content_type= "multipart/form-data" + std::string("; boundary=") + BOUNDARY;

	QueryParams post_params = {
	{"param1", "value1"},
	{"param2", "value2"}
	};

	// Body params will be serialized as URL-encoded
	QueryParams post_body_params = {
		{"body_param1", "body_value1"},
		{"body_param2", "body_value2"}
	};

	// Serialize the body
	std::string post_body = serialize_body(post_body_params, content_type);

	// Headers
	HTTPHeaders post_headers = {
		{"Host", "www.example.com"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type",content_type},
		{"Content-Length", std::to_string(post_body.size())}
	};

	// Create the full request string
	std::string post_request = post_request_method + " " + post_request_uri + create_query_string(post_params) + " " + post_request_version + "\r\n";
	post_request += create_headers_string(post_headers) + "\r\n"; // Add headers
	post_request += post_body; // Add serialized body

	int postRequestResult = http_client->post(post_request_uri, post_request_version, post_headers, post_params, post_body, post_body_params);
	ASSERT_EQ(postRequestResult, RESULT_SUCCESS);

	std::string received_request;
	int request_size = post_request.size();

	http_server->client_socket->recv(received_request, request_size, 0, 0);
	ASSERT_EQ(received_request, post_request);

	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	ASSERT_EQ(HTTP_request.to_string(), post_request);

	int postResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(postResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP POST inet_os Test Passed" << std::endl;
}

TEST_F(HTTP_Tests, HTTPS_GET_inet_os) {

	std::cout << "HTTPS GET inet_os Test" << std::endl;
	set_HTTP_variant(HTTPProtocol::HTTPS);
	connect_to_server();

	std::string get_request_method = "GET";
	std::string get_request_uri = "/msg.txt";
	std::string get_request_version = "HTTP/1.1";

	HTTPHeaders get_headers = {
		{"Host", "www.google.com"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type", "text/plain"},
	};

	QueryParams get_params = {
		{"param1", "value1"},
		{"param2", "value2"},
		{"query", "anotherExample"},
		{"sort", "desc"},
		{"param3", "value3"},
		{"param4", "value4"}
	};

	// Create the query string
	std::string get_request = get_request_method + " " + get_request_uri + create_query_string(get_params) + " " +
		get_request_version + "\r\n" + create_headers_string(get_headers) + "\r\n";

	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params);
	ASSERT_EQ(getRequestResult, RESULT_SUCCESS);

	std::string received_request;
	int request_size = get_request.size();

	http_server->client_socket->recv(received_request, SB_SIZE_DEFAULT, 1, 0);
	ASSERT_EQ(received_request, get_request);
	
	// Create the request object
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	ASSERT_EQ(HTTP_request.to_string(), get_request);

	int getResponseResult = http_server->handle_request(HTTP_request);
	ASSERT_EQ(getResponseResult, RESULT_SUCCESS);

	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	ASSERT_EQ(HTTP_response.to_string(), received_response);

	http_client->handle_response(HTTP_response, HTTP_request.request_path);

	std::cout << "HTTP GET inet_os Test Passed" << std::endl;
}