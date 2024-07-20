#pragma once

#include "HTTP.hpp"

namespace netlab {

	class HTTPServer {
	public:
		netlab::L5_socket* socket;
		std::vector<Resource> resources;

		bool has_resource(std::string request_uri);

		void handle_request(HTTPRequest request);
		void send_response(HTTPResponse response);
	};
}