#pragma once

#include "HTTPServer.hpp"

namespace netlab {

	class HTTPServer_Impl : HTTPServer {
	public:

		// Constructor
		HTTPServer_Impl() = default;

		// Destructor
		~HTTPServer_Impl();

		// HTTP Protocol
		void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_server) override;

		// Establish connection
		void listen_for_connection();
		void accept_connection(inet_os& inet_server);

		// Server Methods
		int handle_request(HTTPRequest& request) override;
		void send_response(HTTPResponse& response, bool close_connection);
		
		// Server Members
		L5_socket* socket;
		L5_socket* client_socket;

		Resource* get_resource(std::string& uri);

	private:
		// Resource Methods
		bool has_resource(std::string& request_path);
		int create_resource(std::string& request_path, std::string& data);
		int remove_resource(std::string& request_path);

		// Server Members
		HTTPProtocol protocol;
		uint16_t port;
		std::vector<Resource> resources;
		bool connection_closed;
	};
}