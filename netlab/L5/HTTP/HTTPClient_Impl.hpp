#pragma once

#include "HTTPClient.hpp"
#include "HTTPServer_Impl.hpp"

namespace netlab {

	class HTTPClient_Impl : HTTPClient {
	public:
		// Constructor
		HTTPClient_Impl() = default;

		// Destructor
		~HTTPClient_Impl();

		// HTTP Protocol
		void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_client) override;

		// Establish connection
		void connect_to_server(inet_os& inet_server, HTTPServer_Impl* http_server);

		// Client Methods
		int get(std::string& uri, std::string& request_version, HTTPHeaders& headers, QueryParams& params) override;
		int post(std::string& uri, std::string& request_version, HTTPHeaders& headers,
			QueryParams& params, std::string& body, QueryParams& body_params) override;

		int handle_response(HTTPResponse& HTTP_response, std::string& requested_resource) override;
	/*protected:*/
		// Client Members
		HTTPProtocol protocol;
		uint16_t port;
		L5_socket* socket;
		std::vector<Resource> resources;
		bool connection_closed;
	};
}
