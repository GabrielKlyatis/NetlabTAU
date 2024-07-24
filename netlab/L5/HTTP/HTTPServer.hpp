#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"

namespace netlab {

	class HTTPServer {
	public:
		HTTPProtocol protocol;
		uint16_t port;
		std::unique_ptr<netlab::L5_socket> socket;
		std::vector<Resource> resources;
		bool connection_closed;

		// Constructor
		HTTPServer(class inet_os &inet_server, HTTPProtocol protocol);

		// Server Methods
		bool has_resource(std::string& request_path);
		int create_resource(std::string& request_path, std::string& data);
		int remove_resource(std::string& request_path);

		HTTPResponse handle_request(HTTPRequest request);
		void send_response(HTTPResponse response);
	};
}