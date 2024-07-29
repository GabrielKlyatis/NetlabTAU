#include "HTTPClient.hpp"

namespace netlab {

	// Destructor
	HTTPClient::~HTTPClient() {
		delete socket;
	}

	// Set the HTTP protocol
	void HTTPClient::set_HTTP_procotol(HTTPProtocol http_protocol, inet_os& inet_client) {
		protocol = http_protocol;
		switch (http_protocol) {
		case HTTPProtocol::HTTP:
			this->port = 80;
			this->socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet_client);
			break;
		case HTTPProtocol::HTTPS:
			this->port = 443;
			this->socket = new tls_socket(inet_client);
			break;
		}
	}

	// Send a GET request
	int HTTPClient::get(std::string& uri, std::string& request_version, HTTPHeaders& headers, QueryParams& params) const {

		int res = RESULT_SUCCESS;
		HTTPRequest http_request;

		http_request.request_method = "GET"; // Request method
		http_request.request_uri = uri;	// Request URI
		if (request_version == "HTTP/1.1") {	// Request version
			http_request.request_version = "HTTP/1.1";
		}
		else {
			std::cerr << "HTTP CLIENT: Invalid request version." << std::endl;
			res = RESULT_FAILURE;
			return res;
		}

		for (auto& header : headers) {	// Request headers
			http_request.insert_header(header.first, header.second);
		}

		for (auto& param : params) {	// Request parameters
			http_request.insert_param(param.first, param.second);
		}

		// Serialize the request
		std::string get_request_string = http_request.to_string();
		size_t size = get_request_string.size();

		// Send the request
		socket->send(get_request_string, size, 0, 0);

		return res;
	}

	// Send a POST request
	int HTTPClient::post(std::string& uri, std::string& request_version, HTTPHeaders& headers, QueryParams& params, 
		std::string& body, QueryParams& body_params) const{

		int res = RESULT_SUCCESS;
		HTTPRequest http_request;

		http_request.request_method = "POST"; // Request method
		http_request.request_uri = uri;	// Request URI

		if (request_version == "HTTP/1.1") {	// Request version
			http_request.request_version = "HTTP/1.1";
		}
		else {
			std::cerr << "HTTP CLIENT: Invalid request version." << std::endl;
			res = RESULT_FAILURE;
			return res;
		}

		for (auto& header : headers) {	// Request headers
			http_request.insert_header(header.first, header.second);
		}

		for (auto& param : params) {	// Request parameters
			http_request.insert_param(param.first, param.second);
		}

		if (body.empty()) {	// Request body
			std::cerr << "HTTP CLIENT: Request body is empty." << std::endl;
			res = RESULT_FAILURE;
			return res;
		}
		http_request.body = body;

		for (auto& body_param : body_params) {	// Request body parameters
			http_request.insert_body_param(body_param.first, body_param.second);
		}

		// Serialize the request
		std::string post_request_string = http_request.to_string();
		size_t size = post_request_string.size();

		// Send the request to the server
		socket->send(post_request_string, size, 0, 0);

		return res;
	}

	int HTTPClient::handle_response(HTTPResponse& HTTP_response, std::string& requested_resource) {

		int res = RESULT_NOT_DEFINED;
		// Check the response status
		if (HTTP_response.status_code == StatusCode::OK) {
			// Save the resource
			Resource resource;
			resource.file_name = requested_resource;
			resource.content = HTTP_response.body;
			resource.content_type = HTTP_response.get_header_value("Content-Type", 0);
			resources.push_back(resource);
			res = RESULT_SUCCESS;
		}
		else if (HTTP_response.status_code == StatusCode::Created) {
			res = RESULT_SUCCESS;
		}
		else {
			std::cerr << "HTTP CLIENT: Request was not successful." << std::endl;
			res = RESULT_FAILURE;
		}
		return res;
	}

} // namespace netlab