#include <WinSock2.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <string>

#include "L5/HTTP/HTTPServer_Impl.hpp"
#include "L5/HTTP/HTTPClient_Impl.hpp"
#include "L5/tls_socket.h"
#include "L5/L5.h"
#include "L4/tcp_reno.h"
#include "L3/L3.h"
#include "L2/L2.h"
#include "L2/L2_ARP.h"
#include "L1/NIC.h"

/**********************************************************************************************************/
/*
	Relevant header files:
		* HTTP.hpp - Containing the HTTP data structures, headers, and the HTTP request/response classes.
		* HTTPClient.hpp, HTTPServer.hpp - Containing the HTTP client and server interfaces.
		* HTTPClient_Impl.hpp, HTTPServer_Impl.hpp - Containing the HTTP client and server implementations.
*/
/**********************************************************************************************************/

using namespace netlab;

// Forward declarations
void HTTP_GET();
void HTTP_POST();

/************************************************************************************/
/*									Utility Functions								*/
/************************************************************************************/

void set_HTTP_variant(HTTPServer_Impl* http_server, HTTPClient_Impl* http_client, inet_os& inet_server, inet_os& inet_client,
	HTTPProtocol http_protocol) {
	http_server->set_HTTP_procotol(http_protocol, inet_server);
	http_client->set_HTTP_procotol(http_protocol, inet_client);
}

void connect_to_server(HTTPServer_Impl* http_server, HTTPClient_Impl* http_client, inet_os& inet_server) {
	http_server->listen_for_connection();
	http_client->connect_to_server(inet_server, http_server);
	http_server->accept_connection(inet_server);
}

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
	std::vector<std::string> default_request_headers_order = { "Host" ,"User-Agent", "Connection", "Content-Type", "Content-Length" };

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

std::wstring string_to_wstring(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

/************************************************************************************/
/*							Main (Calling both GET & POST)							*/
/************************************************************************************/

void main(int argc, char* argv[]) {
	HTTP_GET();
	HTTP_POST();
}

/************************************************************************************/
/*										HTTP GET									*/
/************************************************************************************/

void HTTP_GET() {

	/************************************************************************************/
	/*									Setup of lower levels							*/
	/************************************************************************************/

	// Declaring the client 
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "ip src 10.0.0.10 or arp");

	// Declaring the client's datalink layer
	L2_impl datalink_client(inet_client);

	// Setting up the client's network layer.
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();

	// Declaring the ARP of the client.
	L2_ARP_impl arp_client(inet_client, 10, 10000);

	// Declaring the server
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "ip src 10.0.0.15 or arp");

	// Declaring the server's datalink layer
	L2_impl datalink_server(inet_server);

	// Declaring the ARP of the server.
	L2_ARP_impl arp_server(inet_server, 10, 10000);

	// Setting up the server.
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L4_TCP_impl(inet_server), protosw::SWPROTO_TCP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();

	// Sniffer spawning.
	inet_client.connect(0U);
	inet_server.connect(0U);

	/************************************************************************************/
	/*									 HTTP GET Flow									*/
	/************************************************************************************/

	// Create the HTTP server and client objects
	HTTPServer_Impl* http_server = new HTTPServer_Impl();
	HTTPClient_Impl* http_client = new HTTPClient_Impl();

	std::cout << "HTTP GET inet_os Test" << std::endl;

	// Set the HTTP variant and connect to the server
	set_HTTP_variant(http_server, http_client, inet_server, inet_client, HTTPProtocol::HTTP);
	connect_to_server(http_server, http_client, inet_server);

	// Create the GET request
	std::string get_request_method = "GET";
	std::string get_request_uri = "/NetlabTAU.html";
	std::string get_request_version = "HTTP/1.1";

	// Request headers
	HTTPHeaders get_headers = {
		{"Host", "www.NetlabTAU.TAU"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type", "text/html"},
	};

	// Request params
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

	// Send the GET request
	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params);

	// Receive the GET request
	std::string received_request;
	int request_size = get_request.size();
	http_server->client_socket->recv(received_request, request_size, 0, 0);

	// The server creates the request object, handles it and sends the response back to the client in the backend.
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	int getResponseResult = http_server->handle_request(HTTP_request);

	// The client receives the response from the server.
	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	http_client->handle_response(HTTP_response, HTTP_request.request_uri);

	// Accessing the resource obtained from the server - on the client side
	Resource* obtained_resource = http_client->get_resource(get_request_uri);
	if (obtained_resource) {
		ShellExecute(NULL, L"open", string_to_wstring(INET_EXPLORER).c_str(),
			string_to_wstring(obtained_resource->file_name).c_str(), NULL, SW_SHOWNORMAL);
	}

	std::cout << "HTTP GET inet_os Test Passed" << std::endl << std::endl;

	// Clean up
	http_client->socket->shutdown(SD_SEND);
	http_server->client_socket->shutdown(SD_RECEIVE);

	std::this_thread::sleep_for(std::chrono::seconds(1));

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();

	std::this_thread::sleep_for(std::chrono::seconds(2));
}

/************************************************************************************/
/*										HTTP POST									*/
/************************************************************************************/

void HTTP_POST() {

	/************************************************************************************/
	/*									Setup of lower levels							*/
	/************************************************************************************/

	// Declaring the client 
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "ip src 10.0.0.10 or arp");

	// Declaring the client's datalink layer
	L2_impl datalink_client(inet_client);

	// Setting up the client's network layer.
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L4_TCP_impl(inet_client), protosw::SWPROTO_TCP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();

	// Declaring the ARP of the client.
	L2_ARP_impl arp_client(inet_client, 10, 10000);

	// Declaring the server
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "ip src 10.0.0.15 or arp");

	// Declaring the server's datalink layer
	L2_impl datalink_server(inet_server);

	// Declaring the ARP of the server.
	L2_ARP_impl arp_server(inet_server, 10, 10000);

	// Setting up the server.
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L4_TCP_impl(inet_server), protosw::SWPROTO_TCP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();

	// Sniffer spawning.
	inet_client.connect(0U);
	inet_server.connect(0U);

	/************************************************************************************/
	/*									 HTTP POST Flow									*/
	/************************************************************************************/

	// Create the HTTP server and client objects
	HTTPServer_Impl* http_server = new HTTPServer_Impl();
	HTTPClient_Impl* http_client = new HTTPClient_Impl();

	std::cout << "HTTP POST inet_os Test" << std::endl;

	// Set the HTTP variant and connect to the server
	set_HTTP_variant(http_server, http_client, inet_server, inet_client, HTTPProtocol::HTTP);
	connect_to_server(http_server, http_client, inet_server);

	// Read the client file
	std::string clientFilePath = std::string(CLIENT_HARD_DRIVE) + "/clientFile.html";
	std::ifstream clientFile(clientFilePath, std::ios::in | std::ios::binary);
	std::ostringstream fileStream;
	fileStream << clientFile.rdbuf();
	std::string clientFileContents = fileStream.str();
	clientFile.close();

	// Create the POST request
	std::string post_request_method = "POST";
	std::string post_request_uri = "/clientFile.html"; // Full Request URI = Request path + Query string
	std::string post_request_version = "HTTP/1.1";

	// Post params
	QueryParams post_params = {
	{"param1", "value1"},
	{"param2", "value2"},
	{"query", "anotherExample"},
	{"sort", "desc"},
	{"param3", "value3"},
	{"param4", "value4"}
	};

	// Body params will be serialized as URL-encoded
	QueryParams post_body_params = {{"html_content", clientFileContents}};

	// Serialize the body
	std::string post_body = serialize_body(post_body_params, "multipart/form-data");

	// Request headers
	HTTPHeaders post_headers = {
		{"Host", "www.HTTPClient.TAU"},
		{"User-Agent", netlab::get_user_agent()},
		{"Connection", "close"},
		{"Content-Type", "multipart/form-data; boundary=inet_os_boundary"},
		{"Content-Length", std::to_string(post_body.size())}
	};

	// Create the full request string
	std::string post_request = post_request_method + " " + post_request_uri + create_query_string(post_params) + " " + post_request_version + "\r\n";
	post_request += create_headers_string(post_headers) + "\r\n"; // Add headers
	post_request += post_body; // Add serialized body

	// Send the POST request
	int postRequestResult = http_client->post(post_request_uri, post_request_version, post_headers, post_params, post_body, post_body_params);

	// Server receives the POST request
	std::string received_request;
	int request_size = post_request.size();
	http_server->client_socket->recv(received_request, request_size, 0, 0);

	// The server creates the request object, handles it and sends the response back to the client in the backend.
	HTTPRequest HTTP_request;
	HTTP_request.parse_request(received_request);
	int postResponseResult = http_server->handle_request(HTTP_request);

	// The client receives the response from the server.
	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	http_client->handle_response(HTTP_response, HTTP_request.request_uri);

	// Accessing the resource obtained from the client - on the server side
	Resource* obtained_resource = http_server->get_resource(post_request_uri);
	if (obtained_resource) {
		ShellExecute(NULL, L"open", string_to_wstring(INET_EXPLORER).c_str(),
			string_to_wstring(obtained_resource->file_name).c_str(), NULL, SW_SHOWNORMAL);
	}

	std::cout << "HTTP POST inet_os Test Passed" << std::endl;

	// Clean up
	http_client->socket->shutdown(SD_SEND);
	http_server->client_socket->shutdown(SD_RECEIVE);
}