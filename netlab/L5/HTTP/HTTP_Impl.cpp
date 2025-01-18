#include "HTTPClient_Impl.hpp"
#include "HTTPServer_Impl.hpp"

using namespace netlab;

/**********************************************************************************************/
/*											Request								              */
/**********************************************************************************************/

int HTTPRequest::parse_request(const std::string& request_string) {
	int res = RESULT_NOT_DEFINED;

	// Parse Method (e.g., GET, POST)
	size_t method_end = request_string.find(' ');
	if (method_end != std::string::npos) {
		request_method = request_string.substr(0, method_end); // GET | POST
		size_t uri_end = request_string.find(' ', method_end + 1);
		if (uri_end != std::string::npos) {
			// Parse URI
			request_uri = request_string.substr(method_end + 1, uri_end - method_end - 1); // URI

			// Parse Query Parameters (if any)
			size_t query_start = request_uri.find('?');
			if (query_start != std::string::npos) {
				parse_query_params(request_uri.substr(query_start + 1));
				request_uri = request_uri.substr(0, query_start); // Parse path without query
			}

			// Parse HTTP Version
			size_t version_end = request_string.find('\r', uri_end + 1);
			if (version_end != std::string::npos) {
				request_version = request_string.substr(uri_end + 1, version_end - uri_end - 1); // HTTP Version
			}

			// Parse Headers
			std::vector<std::string> header_lines = split_lines(request_string.substr(version_end + R_N_OFFSET));
			res = parse_headers(header_lines); // Header Name, Header Value
			if (res != RESULT_SUCCESS) {
				return RESULT_FAILURE;
			}

			// If POST request, parse the body
			if (request_method == "POST") {
				size_t content_length = get_header_value_u64("Content-Length", 0);

				// Extract the Content-Type header to determine how to parse the body
				std::string content_type = get_header_value("Content-Type", 0);

				// Locate the start of the body
				size_t body_start_pos = request_string.find("\r\n\r\n") + 2 * R_N_OFFSET;
				std::string body_content = request_string.substr(body_start_pos);

				// Ensure the body size matches Content-Length
				if (body_content.size() < content_length) {
					std::cerr << "Body size is less than Content-Length" << std::endl;
					return RESULT_FAILURE;
				}

				// Store raw body
				body = parse_body(body_content, content_type);
			}
		}
	}

	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to parse the request." << std::endl;
		return RESULT_FAILURE;
	}

	return RESULT_SUCCESS;
}

std::string HTTPRequest::to_string() {
	std::string request_string = "";

	// Serialize the query parameters
	std::string query_string = "";
	for (auto& param : query_params) {
		query_string += param.first + "=" + param.second + "&";
	}
	if (!query_string.empty()) {
		query_string.pop_back(); // Remove the last '&'
	}

	// Add the query params to the request URI
	if (!query_string.empty()) {
		request_string += request_method + " " + request_uri + "?" + query_string + " " + request_version + "\r\n";
	}
	else {
		request_string += request_method + " " + request_uri + " " + request_version + "\r\n";
	}

	// Serialize the headers
	for (auto& header : headers_order) {
		if (headers.find(header) != headers.end()) {
			if (request_method == "POST" && header == "Content-Length") continue; // Skip Content-Length (added later)
			std::string header_value = headers.find(header)->second;
			request_string += header + ": " + header_value + "\r\n";
		}
	}

	// Serialize the body (if any, for POST requests)
	std::string serialized_body = "";
	if (request_method == "POST") {
		// Get the content type
		std::string content_type = get_header_value("Content-Type", 0);
		// Serialize the body using the appropriate method based on Content-Type
		serialized_body = serialize_body(body_params, content_type);

		// Add Content-Length header (must be after body is serialized)
		request_string += "Content-Length: " + std::to_string(serialized_body.size()) + "\r\n\r\n";

		// Add the serialized body
		request_string += serialized_body;
	}
	else {
		// End of headers
		request_string += "\r\n";
	}

	return request_string;
}

/**********************************************************************************************/
/*											Response					                      */
/**********************************************************************************************/

int HTTPResponse::parse_response(const std::string& response_string) {
	int res = RESULT_NOT_DEFINED;
	// Parse HTTP Version
	size_t version_end = response_string.find(' ');
	if (version_end != std::string::npos) {
		version = response_string.substr(0, version_end); // HTTP Version
		// Parse Status Code
		size_t status_code_end = response_string.find(' ', version_end + 1);
		if (status_code_end != std::string::npos) {
			status_code = static_cast<StatusCode>(std::stoi(response_string.substr(version_end + 1, status_code_end - version_end - 1))); // Status Code
			reason = response_string.substr(status_code_end + 1, response_string.find('\r') - status_code_end - 1); // Reason
			// Parse Headers
			std::vector<std::string> header_lines = split_lines(response_string.substr(response_string.find("\r\n") + R_N_OFFSET));
			res = parse_headers(header_lines); // Header Name, Header Value
			if (res != RESULT_SUCCESS) {
				res = RESULT_FAILURE;
				return res;
			}
			// Parse Body
			size_t body_start = response_string.find("\r\n\r\n") + 2 * R_N_OFFSET;
			body = response_string.substr(body_start);
		}
	}
	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to parse the response." << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}
std::string HTTPResponse::to_string() {
	std::string response_string = "";
	response_string += version + " " + std::to_string(status_code) + " " + reason + "\r\n";
	// Serialize the headers
	for (auto& header : headers_order) {
		std::string header_value = headers.find(header)->second;
		response_string += header + ": " + header_value + "\r\n";
	}
	response_string += "\r\n";
	// Serialize the body
	response_string += body;
	return response_string;
}