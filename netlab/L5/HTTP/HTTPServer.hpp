#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"

namespace netlab {

	class HTTPServer {
	public:
		// Destructor
		~HTTPServer() = default;

		// HTTP Protocol
		virtual void set_HTTP_procotol(HTTPProtocol protocol, inet_os& inet_server) = 0;

		// Server Methods
		virtual int handle_request(HTTPRequest& request) = 0;

	protected:
		// Constructor
		HTTPServer() = default;
	};
}