#include "HTTPClient.hpp"

namespace netlab {

	// Constructor
	HTTPClient::HTTPClient(class inet_os inet_client, HTTPProtocol protocol) {
		switch (protocol) {
		case HTTPProtocol::HTTP:
			this->protocol = HTTPProtocol::HTTP;
			this->port = 80;
			socket = new netlab::L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client);

			break;
		case HTTPProtocol::HTTPS:
			this->protocol = HTTPProtocol::HTTPS;
			this->port = 443;
			socket = new netlab::tls_socket(inet_client);
			break;
		}
	}

} // namespace netlab