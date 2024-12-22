#include "HTTPServer_Impl.hpp"

using namespace netlab;

// Destructor
HTTPServer_Impl::~HTTPServer_Impl() {
	delete socket;
	delete client_socket;
}

// Set the HTTP protocol
void HTTPServer_Impl::set_HTTP_procotol(HTTPProtocol http_protocol, inet_os& inet_server) {
	protocol = http_protocol;
	switch (http_protocol) {
	case HTTPProtocol::HTTP:
		this->port = 80;
		this->socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server);
		break;
	case HTTPProtocol::HTTPS:
		this->port = 443;
		this->socket = new tls_socket(inet_server);
		break;
	default:
		assert(false && "Invalid HTTP protocol.");
	}
}

// Handle the request
int HTTPServer_Impl::handle_request(HTTPRequest& HTTP_request) {

	int res = RESULT_SUCCESS;
	bool close_connection = false;
	HTTPResponse HTTP_response;

	// Update the response date header
	HTTP_response.set_header_value("Date", get_current_time());
	// Update the connection header
	HTTP_response.update_connection_state(HTTP_request);
	HTTPMethod HTTP_method =
		HTTP_request.request_method == "GET" ? HTTPMethod::GET : HTTPMethod::POST; // Only GET and POST methods are supported
	switch (HTTP_method) {
	case HTTPMethod::GET:
		// Check if the server has the requested resource
		if (has_resource(HTTP_request.request_uri)) {
			// Send a 200 OK response
			HTTP_response.status_code = StatusCode::OK;
			HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
			HTTP_response.set_header_value("Content-Type", get_content_type(HTTP_request.request_uri));
			HTTP_response.body = get_file_contents(HTTP_request.request_uri);
			HTTP_response.set_header_value("Content-Length", std::to_string(HTTP_response.body.size()));
		}
		else {
			// Send a 404 Not Found response
			HTTP_response.status_code = StatusCode::NotFound;
			HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
		}
		break;
	case HTTPMethod::POST:
		// Create the resource
		if (create_resource(HTTP_request) == RESULT_SUCCESS) {
			// Send a 201 Created response
			HTTP_response.status_code = StatusCode::Created;
			HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
			HTTP_response.set_header_value("Content-Type", HTTP_request.get_header_value("Content-Type", 0));
		}
		else {
			// Send a 500 Internal Server Error response
			HTTP_response.status_code = StatusCode::InternalServerError;
			HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
			res = RESULT_FAILURE;
		}
		break;
	default:
		break;
	}
	// Send the response
	close_connection = HTTP_response.get_header_value("Connection", 0) == "close";
	send_response(HTTP_response, close_connection);
	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to handle the request." << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}