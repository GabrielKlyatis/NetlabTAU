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
void HTTPS_GET(inet_os& inet_client, inet_os& inet_server, HTTPClient_Impl* http_client, HTTPServer_Impl* http_server);

/************************************************************************************/
/*							  Main (Calling both GET)								*/
/************************************************************************************/

void main(int argc, char* argv[]) {

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
	/*						Setup of HTTP objects and server boot						*/
	/************************************************************************************/

	// Create the HTTPS server and client objects
	HTTPServer_Impl* http_server = new HTTPServer_Impl();
	HTTPClient_Impl* http_client = new HTTPClient_Impl();

	// Run the HTTPS Server
	http_server->run_server(inet_server, HTTPProtocol::HTTPS);

	// Send the GET and POST requests to the server
	HTTPS_GET(inet_client, inet_server, http_client, http_server);

	// Clean up
	http_client->socket->shutdown(SD_SEND);

	std::this_thread::sleep_for(std::chrono::seconds(1));

	inet_client.stop_fasttimo();
	inet_client.stop_slowtimo();

	inet_server.stop_fasttimo();
	inet_server.stop_slowtimo();
}

/************************************************************************************/
/*										HTTPS GET									*/
/************************************************************************************/

void HTTPS_GET(inet_os& inet_client, inet_os& inet_server, HTTPClient_Impl* http_client, HTTPServer_Impl* http_server) {

	std::cout << "HTTP GET inet_os Test" << std::endl;

	// Set the HTTP variant (HTTP/HTTPS).
	http_client->set_HTTP_procotol(HTTPProtocol::HTTPS, inet_client);

	// Connect to the server
	http_client->connect_to_server(inet_server, http_server);

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
	};

	std::this_thread::sleep_for(std::chrono::seconds(8)); // Wait for the server to be ready

	// Send the GET request
	int getRequestResult = http_client->get(get_request_uri, get_request_version, get_headers, get_params);

	// The client receives the response from the server.
	std::string received_response;
	http_client->socket->recv(received_response, SB_SIZE_DEFAULT, 1, 0);
	HTTPResponse HTTP_response(received_response);
	http_client->handle_response(HTTP_response, get_request_uri);

	// Accessing the resource obtained from the server - on the client side
	char currentPath[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, currentPath);
	Resource* obtained_resource = http_client->get_resource(get_request_uri);
	if (obtained_resource) {
		std::string fullpath = std::string(currentPath) + "/" + obtained_resource->file_name;
		ShellExecuteA(nullptr, "open", G_CHROME, fullpath.c_str(), NULL, SW_SHOWNORMAL);
	}

	std::cout << "HTTP GET inet_os Test Passed" << std::endl << std::endl;
}