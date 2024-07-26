#include "HTTPServer.hpp"

namespace netlab {

	// Constructor
	HTTPServer::HTTPServer(inet_os &inet_server, HTTPProtocol http_protocol)
		: protocol(http_protocol), port(0), socket(nullptr), connection_closed(true) {
		switch (http_protocol) {
		case HTTPProtocol::HTTP:
			this->port = 80;
			this->socket = std::make_unique<netlab::L5_socket_impl>(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_server);
			break;
		case HTTPProtocol::HTTPS:
			this->port = 443;
			this->socket = std::make_unique<netlab::tls_socket>(inet_server);
			break;
		}
	}

    // Check if the server has the requested resource
    bool HTTPServer::has_resource(std::string& request_path) {
		std::string full_path = SERVER_FILESYSTEM + request_path;
		std::ifstream file(full_path);
		return file.good();
    }

	int HTTPServer::remove_resource(std::string& request_path) {
		std::string full_path = SERVER_FILESYSTEM + request_path;
		std::remove(full_path.c_str());
		if (has_resource(full_path)) {
			std::cerr << "Failed to remove the resource from the server." << full_path << std::endl;
			return RESULT_FAILURE;
		}
		else {
			std::cout << "No such resource on the server." << full_path << std::endl;
		}
		return RESULT_SUCCESS;
	}

	int HTTPServer::create_resource(std::string& request_path, std::string& data) {
		int res = RESULT_NOT_DEFINED;
		std::string full_path = SERVER_FILESYSTEM + request_path;
		if (has_resource(full_path)) {
			res = remove_resource(full_path);
			if (res != RESULT_SUCCESS) {
				return RESULT_FAILURE;
			}
		}
		std::ofstream resource_file(full_path.c_str(), std::ios::binary);
		if (!resource_file.is_open()) {
			std::cerr << "Failed to create resource on the server. " << full_path << std::endl;
			return RESULT_FAILURE;
		}
		resource_file << data;
		resource_file.close();
		return RESULT_SUCCESS;
	}

	// Handle the request
	HTTPResponse HTTPServer::handle_request(HTTPRequest HTTP_request) {

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
				if (has_resource(HTTP_request.request_path)) {
					// Send a 200 OK response
					HTTP_response.status_code = StatusCode::OK;
					HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
					HTTP_response.set_header_value("Content-Type", get_content_type(HTTP_request.request_path));
					HTTP_response.body = get_file_contents(HTTP_request.request_path);
					HTTP_response.set_header_value("Content-Length", std::to_string(HTTP_response.body.size()));
					return HTTP_response;
				}
				else {
					// Send a 404 Not Found response
					HTTP_response.status_code = StatusCode::NotFound;
					HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);

					send_response(HTTP_response);
				}
				break;
			case HTTPMethod::POST:
				// Create the resource
				if (create_resource(HTTP_request.request_path, HTTP_request.body) == RESULT_SUCCESS) {
					// Send a 201 Created response
					HTTP_response.status_code = StatusCode::Created;
					HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
					HTTP_response.set_header_value("Content-Type", HTTP_request.get_header_value("Content-Type", 0));
					send_response(HTTP_response);
				}
				else {
					// Send a 500 Internal Server Error response
					HTTP_response.status_code = StatusCode::InternalServerError;
					HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);

					send_response(HTTP_response);
				}
				break;
			default:
				break;		
		}
		return HTTP_response;
	}

	// Send the response
	void HTTPServer::send_response(HTTPResponse response) {
		// TODO
	}

} // namespace netlab