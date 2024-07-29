#include "HTTPServer.hpp"

namespace netlab {


	// Destructor
	HTTPServer::~HTTPServer() {
		delete socket;
		delete client_socket;
	}

	// Set the HTTP protocol
	void HTTPServer::set_HTTP_procotol(HTTPProtocol http_protocol, inet_os& inet_server) {
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

    // Check if the server has the requested resource
    bool HTTPServer::has_resource(std::string& request_path) {
		bool file_exists = false;
		std::string full_path = SERVER_FILESYSTEM + request_path;
		std::ifstream file(full_path);
		file_exists = file.good();
		file.close();
		return file_exists;
    }

	// Remove the resource from the server
	int HTTPServer::remove_resource(std::string& request_path) {
		int res = RESULT_NOT_DEFINED;
		std::string full_path = SERVER_FILESYSTEM + request_path;
		std::remove(full_path.c_str());
		if (has_resource(full_path)) {
			std::cerr << "HTTP SERVER: Failed to remove the resource from the server." << full_path << std::endl;
			res = RESULT_FAILURE;
		}
		else {
			res = RESULT_SUCCESS;
		}
		return res;
	}

	// Create the resource on the server
	int HTTPServer::create_resource(std::string& request_path, std::string& data) {
		int res = RESULT_SUCCESS;
		std::string full_path = SERVER_FILESYSTEM + request_path;
		if (has_resource(full_path)) {
			res = remove_resource(full_path);
			if (res != RESULT_SUCCESS) {
				res = RESULT_FAILURE;
				return res;
			}
		}
		std::ofstream resource_file(full_path.c_str(), std::ios::binary);
		if (!resource_file.is_open()) {
			std::cerr << "HTTP SERVER: Failed to create resource on the server." << full_path << std::endl;
			res = RESULT_FAILURE;
			return res;
		}
		resource_file << data;
		resource_file.close();
		if (res != RESULT_SUCCESS) {
			std::cerr << "HTTP SERVER: Failed to create resource on the server." << full_path << std::endl;
			res = RESULT_FAILURE;
		}
		return res;
	}

	// Handle the request
	int HTTPServer::handle_request(HTTPRequest& HTTP_request) {

		int res = RESULT_SUCCESS;
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
				}
				else {
					// Send a 404 Not Found response
					HTTP_response.status_code = StatusCode::NotFound;
					HTTP_response.reason = HTTPResponse::status_message(HTTP_response.status_code);
				}
				break;
			case HTTPMethod::POST:
				// Create the resource
				if (create_resource(HTTP_request.request_path, HTTP_request.body) == RESULT_SUCCESS) {
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
		send_response(HTTP_response);
		if (res != RESULT_SUCCESS) {
			std::cerr << "Failed to handle the request." << std::endl;
			res = RESULT_FAILURE;
		}
		return res;
	}

	// Send the response to the client
	void HTTPServer::send_response(HTTPResponse& HTTP_response) {
		
		// Serialize the response
		std::string response_string = HTTP_response.to_string();
		size_t size = response_string.size();

		// Send the response to the client
		client_socket->send(response_string, size, 0, 0);
	}

} // namespace netlab