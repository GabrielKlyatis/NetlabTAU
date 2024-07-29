#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"

namespace netlab {

	class HTTPServer {
	public:
		HTTPProtocol protocol;
		uint16_t port;
		L5_socket* socket;
		L5_socket* client_socket;
		std::vector<Resource> resources;
		bool connection_closed;

		// Constructor
		HTTPServer() = default;

		// Destructor
		~HTTPServer();

		// HTTP Protocol
		void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_server);

		// Server Methods
		bool has_resource(std::string& request_path);
		int create_resource(std::string& request_path, std::string& data);
		int remove_resource(std::string& request_path);

		int handle_request(HTTPRequest& request);
		void send_response(HTTPResponse& response);
	};
}