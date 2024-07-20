#pragma once

#include "../../infra/inet_os.hpp"
#include "HTTP.hpp"


namespace netlab {

	class HTTPClient {
	public:
		HTTPProtocol protocol;
		netlab::L5_socket* socket;
		uint16_t port;
		std::vector<Resource> resources;

		// Constructor
		HTTPClient(class inet_os inet_client, HTTPProtocol protocol);

		void get();
		void post();
		void handle_response(HTTPResponse response);
	};
}
