#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"


namespace netlab {

	class HTTPClient {
	public:
		// Client Members
		HTTPProtocol protocol;
		uint16_t port;
		L5_socket* socket;
		std::vector<Resource> resources;
		bool connection_closed;
		
		// Constructor
		HTTPClient() = default;

		// Destructor
		~HTTPClient();

		// HTTP Protocol
		void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_client);

		// Client Methods
		int get(std::string& uri, std::string& request_version, HTTPHeaders& headers, QueryParams& params) const;
		int post(std::string& uri, std::string& request_version, HTTPHeaders& headers, 
			QueryParams& params, std::string& body, QueryParams& body_params) const;

		int handle_response(HTTPResponse& HTTP_response, std::string& requested_resource);
	};
}
