#include "HTTPClient.hpp"

namespace netlab {

	// Constructor
	HTTPClient::HTTPClient(inet_os &inet_server, HTTPProtocol http_protocol)
		: protocol(http_protocol), port(0), socket(nullptr) {
		switch (http_protocol) {
		case HTTPProtocol::HTTP:
			this->port = 80;
			this->socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server);
			break;
		case HTTPProtocol::HTTPS:
			this->port = 443;
			this->socket = new tls_socket(inet_server);
			break;
		}
	}

	// Destructor
	HTTPClient::~HTTPClient() {
		delete socket;
	}

	void HTTPClient::get(std::string get_request) {
		
		// Send the request
		socket->send(get_request.c_str(), get_request.size(), 0 , 0);

		// Receive the response
		std::string response;
		std::string recv_buffer;
		int bytes_received = 0;
		while ((bytes_received = socket->recv(recv_buffer, sizeof(recv_buffer), 0, 0)) > 0) {
			response.append(recv_buffer, bytes_received);
		}

		// Parse the response
		HTTPResponse http_response;
		//http_response.parse(response);

		// Handle the response
		handle_response(http_response, netlab::HTTPMethod::GET);

	}

	void HTTPClient::post(std::string post_request) {
		
		// Send the request
		socket->send(post_request.c_str(), post_request.size(), 0, 0);

		// Receive the response
		std::string response;
		std::string recv_buffer;
		int bytes_received = 0;
		while ((bytes_received = socket->recv(recv_buffer, sizeof(recv_buffer), 0, 0)) > 0) {
			response.append(recv_buffer, bytes_received);
		}

		// Parse the response
		HTTPResponse http_response;
		//http_response.parse(response);

		// Handle the response
		handle_response(http_response, netlab::HTTPMethod::POST);
	}

	void HTTPClient::handle_response(HTTPResponse response, HTTPMethod http_method) {
		switch (http_method) {
			case HTTPMethod::GET:
				// TODO
				break;
			case HTTPMethod::POST:
				// TODO
				break;
			default:
				break;
		}
	}

} // namespace netlab