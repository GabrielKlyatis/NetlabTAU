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

		// Constructor
		HTTPClient(class inet_os &inet_client, HTTPProtocol protocol);

		// Destructor
		~HTTPClient();

		// Client Methods
		void get(std::string get_request);
		void post(std::string post_request);
		void handle_response(HTTPResponse response, HTTPMethod http_method);
	};
}
