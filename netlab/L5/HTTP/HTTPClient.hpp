#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"

namespace netlab {

	class HTTPClient {
	protected:
		// Constructor
		HTTPClient() = default;
	public:
		// Destructor
		~HTTPClient() = default;
		// HTTP Protocol
		virtual void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_client) = 0;

		// Client Methods
		virtual int get(std::string& uri, std::string& request_version, HTTPHeaders& headers, QueryParams& params) = 0;
		virtual int post(std::string& uri, std::string& request_version, HTTPHeaders& headers,
			QueryParams& params, std::string& body, QueryParams& body_params) = 0;

		virtual int handle_response(HTTPResponse& HTTP_response, std::string& requested_resource) = 0;

		L5_socket* socket;
	};
}
