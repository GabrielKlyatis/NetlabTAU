#include "HTTP.hpp"

using namespace netlab;

/**********************************************************************************************/
/*								      Utility Functions								          */
/**********************************************************************************************/

std::string netlab::get_current_time() {
	std::time_t now = std::time(nullptr);
	char buf[100];
	std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now));
	return std::string(buf);
}

std::vector<std::string> split_lines(const std::string& str) {
	std::vector<std::string> lines;
	std::istringstream stream(str);
	std::string line;
	while (std::getline(stream, line, '\r')) {
		if (line.size() > 0 && line[0] == '\n') {
			line.erase(line.begin());
		}
		if (!line.empty()) {
			lines.push_back(line);
		}
		if (line.empty() || line == "\n") {
			break;
		}
	}
	return lines;
}

std::string netlab::get_content_type(std::string& resource_path) {

	std::string resource_extension = resource_path.substr(resource_path.find_last_of('.') + 1);
	if (resource_extension == "html") {
		return "text/html";
	}
	else if (resource_extension == "css") {
		return "text/css";
	}
	else if (resource_extension == "js") {
		return "text/javascript";
	}
	else if (resource_extension == "png") {
		return "image/png";
	}
	else if (resource_extension == "jpg" || resource_extension == "jpeg") {
		return "image/jpeg";
	}
	else if (resource_extension == "gif") {
		return "image/gif";
	}
	else if (resource_extension == "svg") {
		return "image/svg+xml";
	}
	else if (resource_extension == "ico") {
		return "image/x-icon";
	}
	else if (resource_extension == "json") {
		return "application/json";
	}
	else if (resource_extension == "pdf") {
		return "application/pdf";
	}
	else if (resource_extension == "zip") {
		return "application/zip";
	}
	else if (resource_extension == "xml") {
		return "application/xml";
	}
	else if (resource_extension == "mp4") {
		return "video/mp4";
	}
	else if (resource_extension == "mpeg") {
		return "video/mpeg";
	}
	else if (resource_extension == "webm") {
		return "video/webm";
	}
	else if (resource_extension == "ogg") {
		return "video/ogg";
	}
	else if (resource_extension == "mp3") {
		return "audio/mp3";
	}
	else if (resource_extension == "wav") {
		return "audio/wav";
	}
	else if (resource_extension == "flac") {
		return "audio/flac";
	}
	else if (resource_extension == "aac") {
		return "audio/aac";
	}
	else if (resource_extension == "midi") {
		return "audio/midi";
	}
	else if (resource_extension == "weba") {
		return "audio/webm";
	}

	return "text/plain";
}

std::string netlab::get_file_contents(const std::string& resource_path) {
	std::string full_path = SERVER_FILESYSTEM + resource_path;
	std::ifstream file(full_path);
	if (!file.is_open()) {
		throw std::runtime_error("Unable to open file: " + full_path);
	}
	std::stringstream buffer;
	buffer << file.rdbuf();
	return buffer.str();
}

std::string netlab::url_decode(const std::string& str) {
	std::string decoded;
	char temp[3] = { 0 };
	for (size_t i = 0; i < str.length(); ++i) {
		if (str[i] == '%') {
			temp[0] = str[i + 1];
			temp[1] = str[i + 2];
			decoded += static_cast<char>(std::strtol(temp, nullptr, 16));
			i += 2;
		}
		else if (str[i] == '+') {
			decoded += ' ';
		}
		else {
			decoded += str[i];
		}
	}
	return decoded;
}

/**********************************************************************************************/
/*											Request								              */
/**********************************************************************************************/

HTTPRequest::HTTPRequest() : request_method(""), request_uri(""), request_path(""),
request_version("HTTP/1.1"), headers_order(default_request_headers_order), body("") {}

HTTPRequest::HTTPRequest(const std::string& request_string) {
	parse_request(request_string);
}

// HTTPHeaders
bool HTTPRequest::has_header(const std::string& key) {
	return headers.find(key) != headers.end();
}
std::string HTTPRequest::get_header_value(const std::string& key, size_t id = 0) {
	auto range = headers.equal_range(key);
	auto it = range.first;
	std::advance(it, id);
	if (it != range.second) {
		return it->second;
	}
	return std::string();
}
uint64_t HTTPRequest::get_header_value_u64(const std::string& key, size_t id = 0) {
	auto range = headers.equal_range(key);
	auto it = range.first;
	std::advance(it, id);
	if (it != range.second) {
		return std::stoull(it->second);
	}
	return 0;
}
void HTTPRequest::set_header_value(const std::string& key, const std::string& val) {
	auto range = headers.equal_range(key);
	for (auto it = range.first; it != range.second; ++it) {
		it->second = val;
	}
}
void HTTPRequest::insert_header(const std::string& key, const std::string& val) {
	if (has_header(key)) {
		set_header_value(key, val);
		return;
	}
	headers.emplace(key, val);
}
int HTTPRequest::parse_headers(const std::vector<std::string>& lines) {
	int res = RESULT_NOT_DEFINED;
	for (size_t i = 0; i < lines.size(); ++i) {
		size_t pos = lines[i].find(':');
		if (pos != std::string::npos) {
			std::string field_name = lines[i].substr(0, pos);
			// Check if the header is supported
			if (field_name == "Host" || field_name == "User-Agent" || field_name == "Accept" ||
				field_name == "Content-Type" || field_name == "Content-Length" || field_name == "Connection") {
				std::string field_value = lines[i].substr(pos + 2); // Skip ": " (colon and space)
				insert_header(field_name, field_value);
				res = RESULT_SUCCESS;
			}
			else {
				std::cerr << "Unsupported Header: " << field_name << std::endl;
				return RESULT_FAILURE;
			}
		}
	}
	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to parse headers." << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}

// QueryParams
bool HTTPRequest::has_param(const std::string& key) {
	return query_params.find(key) != query_params.end();
}
std::string HTTPRequest::get_param_value(const std::string& key, size_t id = 0) {
	auto range = query_params.equal_range(key);
	auto it = range.first;
	std::advance(it, id);
	if (it != range.second) {
		return it->second;
	}
	return std::string();
}
void HTTPRequest::insert_param(const std::string& key, const std::string& val) {
	if (has_param(key)) {
		return;
	}
	query_params.emplace(key, val);
}
void HTTPRequest::parse_query_params(const std::string& query) {
	std::istringstream query_stream(query);
	std::string pair;
	while (std::getline(query_stream, pair, '&')) {
		size_t pos = pair.find('=');
		if (pos != std::string::npos) {
			std::string key = pair.substr(0, pos);
			std::string value = pair.substr(pos + 1);
			insert_param(key, value);
		}
	}
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> POST <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

// Function to serialize data as application/x-www-form-urlencoded
std::string HTTPRequest::serialize_urlencoded(const QueryParams& params) {
	std::stringstream body_stream;
	bool first = true;

	for (const auto& param : params) {
		if (!first) body_stream << "&";
		body_stream << param.first << "=" << param.second;
		first = false;
	}

	return body_stream.str();
}

// Function to serialize data as multipart/form-data
std::string HTTPRequest::serialize_multipart(const QueryParams& params, const std::string& boundary) {
	std::stringstream body_stream;

	for (const auto& param : params) {
		body_stream << "--" << boundary << "\r\n";
		body_stream << "Content-Disposition: form-data; name=\"" << param.first << "\"\r\n\r\n";
		body_stream << param.second << "\r\n";
	}

	body_stream << "--" << boundary << "--\r\n";  // Add closing boundary
	return body_stream.str();
}

// Function to serialize the body
std::string HTTPRequest::serialize_body(const QueryParams& params, const std::string& content_type) {
	if (content_type == "application/x-www-form-urlencoded") {
		return serialize_urlencoded(params);
	}
	else if (content_type == "multipart/form-data") {
		std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
		return serialize_multipart(params, boundary);
	}
	else {
		std::cerr << "Unsupported Content-Type: " << content_type << std::endl;
		return "";
	}
}

// Function to parse application/x-www-form-urlencoded
void HTTPRequest::parse_urlencoded(std::string& unfiltered_body) {
	std::string strippedBody = unfiltered_body;
	std::regex keyValuePairRegex(R"((^|[&\s])([^&=]+)=([^&\s]*)(?=(&|\s|$)))");
	std::smatch match;

	// Remove all key-value pairs
	while (std::regex_search(strippedBody, match, keyValuePairRegex)) {
		// Insert the URL-decoded key-value pair into the body_params map
		std::string key = url_decode(match[2].str());
		std::string value = url_decode(match[3].str());
		insert_body_param(key, value);

		// Remove the matched key-value pair from the string
		strippedBody = match.prefix().str() + match.suffix().str();
	}
}

// Function to parse multipart/form-data
void HTTPRequest::parse_multipart(const std::string& body, const std::string& boundary) {
	std::string delimiter = "--" + boundary;
	std::string end_delimiter = delimiter + "--";
	size_t pos = 0, end_pos = 0;

	// Loop through all parts until the end boundary is found
	while ((pos = body.find(delimiter, pos)) != std::string::npos) {
		pos += delimiter.length();

		// Check if it's the final boundary (end delimiter)
		if (body.substr(pos, 2) == "--") {
			break;  // End boundary found, stop processing
		}

		// Find the next boundary (end of the current part)
		if ((end_pos = body.find(delimiter, pos)) == std::string::npos) {
			break;  // No more parts
		}

		// Extract the part between boundaries
		std::string part = body.substr(pos, end_pos - pos);
		pos = end_pos;

		// Extract the headers and content
		size_t header_end_pos = part.find("\r\n\r\n");
		if (header_end_pos != std::string::npos) {
			std::string headers = part.substr(0, header_end_pos);
			std::string content = part.substr(header_end_pos + 4);  // Skip the \r\n\r\n

			// Extract the form field name from Content-Disposition header
			size_t name_pos = headers.find("name=\"");
			if (name_pos != std::string::npos) {
				name_pos += 6;  // Move past 'name="'
				size_t name_end_pos = headers.find("\"", name_pos);
				if (name_end_pos != std::string::npos) {
					std::string field_name = headers.substr(name_pos, name_end_pos - name_pos);

					// Remove trailing \r\n from content
					if (content.length() >= 2 && content.substr(content.length() - 2) == "\r\n") {
						content = content.substr(0, content.length() - 2);
					}

					// Insert field name and content into the map
					body_params.insert({ field_name, content });
				}
			}
		}
	}
}

// Main function to parse the body
void HTTPRequest::parse_body(const std::string& body, const std::string& content_type) {
	if (content_type == "application/x-www-form-urlencoded") {
		std::string body_copy = body;  // Make a copy because regex modifies the string
		parse_urlencoded(body_copy);
	}
	else if (content_type.find("multipart/form-data") != std::string::npos) {
		// Extract boundary from content_type
		size_t boundary_pos = content_type.find("boundary=");
		if (boundary_pos != std::string::npos) {
			std::string boundary = content_type.substr(boundary_pos + 9);  // Skip 'boundary='
			parse_multipart(body, boundary);
		}
	}
	else {
		std::cerr << "Unsupported Content-Type: " << content_type << std::endl;
	}
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> POST <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

// Body
void HTTPRequest::insert_body_param(const std::string& key, const std::string& val) {
	body_params.emplace(key, val);
}
//void HTTPRequest::parse_body_query_params(std::string& unfiltered_body) {
//	std::string strippedBody = unfiltered_body;
//	std::regex keyValuePairRegex(R"((^|[&\s])([^&=]+)=([^&\s]*)(?=(&|\s|$)))");
//	std::smatch match;
//
//	// Remove all key-value pairs
//	while (std::regex_search(strippedBody, match, keyValuePairRegex)) {
//		// Insert the URL-decoded key-value pair into the body_params map
//		std::string key = url_decode(match[2].str());
//		std::string value = url_decode(match[3].str());
//		insert_body_param(key, value);
//
//		// Remove the matched key-value pair from the string
//		strippedBody = match.prefix().str() + match.suffix().str();
//	}
//}

// Request
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
				size_t content_length = get_header_value_u64("Content-Length");

				// Extract the Content-Type header to determine how to parse the body
				std::string content_type = get_header_value("Content-Type");

				// Locate the start of the body
				size_t body_start_pos = request_string.find("\r\n\r\n") + 2 * R_N_OFFSET;
				std::string body_content = request_string.substr(body_start_pos);

				// Ensure the body size matches Content-Length
				if (body_content.size() < content_length) {
					std::cerr << "Body size is less than Content-Length" << std::endl;
					return RESULT_FAILURE;
				}

				// Use the existing parse_body function to parse the body
				parse_body(body_content, content_type);

				// Store the raw body for further reference if needed
				body = body_content;
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
			if (request_method == "POST" && header == "Content-Length") continue; // Skip Content-Length (added later
			std::string header_value = headers.find(header)->second;
			request_string += header + ": " + header_value + "\r\n";
		}
	}

	// Serialize the body (if any, for POST requests)
	std::string serialized_body = "";
	if (request_method == "POST") {
		// Get the content type
		std::string content_type = get_header_value("Content-Type");
		// Serialize the body using the appropriate method based on Content-Type
		serialized_body = serialize_body(body_params, content_type);

		// Add Content-Length header (must be after body is serialized)
		request_string += "Content-Length: " + std::to_string(serialized_body.size()) + "\r\n";
	}

	// End of headers
	request_string += "\r\n";

	// Append the serialized body (if POST)
	if (request_method == "POST") {
		request_string += serialized_body;
	}

	return request_string;
}

/**********************************************************************************************/
/*											Response					                      */
/**********************************************************************************************/

// Constructor
HTTPResponse::HTTPResponse() : version("HTTP/1.1"), status_code(StatusCode::OK),
reason(status_message(status_code)), headers(default_response_headers),
headers_order(default_response_headers_order), body("") {}

HTTPResponse::HTTPResponse(const std::string& response_string) {
	headers_order = default_response_headers_order;
	parse_response(response_string);
}

std::string HTTPResponse::status_message(StatusCode status_code) {
	switch (status_code) {
		// 1xx Informational
	case StatusCode::Continue: return "Continue";
	case StatusCode::SwitchingProtocols: return "Switching Protocol";
	case StatusCode::Processing: return "Processing";
	case StatusCode::EarlyHints: return "Early Hints";
		// 2xx Success
	case StatusCode::OK: return "OK";
	case StatusCode::Created: return "Created";
	case StatusCode::Accepted: return "Accepted";
	case StatusCode::NonAuthoritativeInformation: return "Non-Authoritative Information";
	case StatusCode::NoContent: return "No Content";
	case StatusCode::ResetContent: return "Reset Content";
	case StatusCode::PartialContent: return "Partial Content";
	case StatusCode::MultiStatus: return "Multi-Status";
	case StatusCode::AlreadyReported: return "Already Reported";
	case StatusCode::IMUsed: return "IM Used";
		// 3xx Redirection
	case StatusCode::MultipleChoices: return "Multiple Choices";
	case StatusCode::MovedPermanently: return "Moved Permanently";
	case StatusCode::Found: return "Found";
	case StatusCode::SeeOther: return "See Other";
	case StatusCode::NotModified: return "Not Modified";
	case StatusCode::UseProxy: return "Use Proxy";
	case StatusCode::Unused: return "unused";
	case StatusCode::TemporaryRedirect: return "Temporary Redirect";
	case StatusCode::PermanentRedirect: return "Permanent Redirect";
		// 4xx Client Error
	case StatusCode::BadRequest: return "Bad Request";
	case StatusCode::Unauthorized: return "Unauthorized";
	case StatusCode::PaymentRequired: return "Payment Required";
	case StatusCode::Forbidden: return "Forbidden";
	case StatusCode::NotFound: return "Not Found";
	case StatusCode::MethodNotAllowed: return "Method Not Allowed";
	case StatusCode::NotAcceptable: return "Not Acceptable";
		// 5xx Server Error
	case StatusCode::NotImplemented: return "Not Implemented";
	case StatusCode::BadGateway: return "Bad Gateway";
	case StatusCode::ServiceUnavailable: return "Service Unavailable";
	case StatusCode::GatewayTimeout: return "Gateway Timeout";
	case StatusCode::HTTPVersionNotSupported: return "HTTP Version Not Supported";
	case StatusCode::VariantAlsoNegotiates: return "Variant Also Negotiates";
	case StatusCode::InsufficientStorage: return "Insufficient Storage";
	case StatusCode::LoopDetected: return "Loop Detected";
	case StatusCode::NotExtended: return "Not Extended";
	case StatusCode::NetworkAuthenticationRequired: return "Network Authentication Required";

	default:
	case StatusCode::InternalServerError: return "Internal Server Error";
	}
}

// HTTPHeaders
bool HTTPResponse::has_header(const std::string& key) {
	return headers.find(key) != headers.end();
}
std::string HTTPResponse::get_header_value(const std::string& key, size_t id = 0) {
	auto range = headers.equal_range(key);
	auto it = range.first;
	std::advance(it, id);
	if (it != range.second) {
		return it->second;
	}
	return std::string();
}
uint64_t HTTPResponse::get_header_value_u64(const std::string& key, size_t id = 0) {
	auto range = headers.equal_range(key);
	auto it = range.first;
	std::advance(it, id);
	if (it != range.second) {
		return std::stoull(it->second);
	}
	return 0;
}
void HTTPResponse::set_header_value(const std::string& key, const std::string& val) {
	auto range = headers.equal_range(key);
	for (auto it = range.first; it != range.second; ++it) {
		it->second = val;
	}
}
void HTTPResponse::insert_header(const std::string& key, const std::string& val) {
	if (has_header(key)) {
		set_header_value(key, val);
		return;
	}
	headers.emplace(key, val);
}
int HTTPResponse::parse_headers(const std::vector<std::string>& lines) {
	int res = RESULT_NOT_DEFINED;
	for (size_t i = 0; i < lines.size(); ++i) {
		size_t pos = lines[i].find(':');
		if (pos != std::string::npos) {
			std::string field_name = lines[i].substr(0, pos);
			// Check if the header is supported
			if (field_name == "Date" || field_name == "Server" || field_name == "Content-Type" ||
				field_name == "Content-Length" || field_name == "Connection" || field_name == "Location") {
				std::string field_value = lines[i].substr(pos + 2); // Skip ": " (colon and space)
				insert_header(field_name, field_value);
				res = RESULT_SUCCESS;
			}
			else {
				std::cout << "Unsupported Header: " << field_name << std::endl;
				res = RESULT_FAILURE;
				return res;
			}
		}
	}
	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to parse headers." << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}
int HTTPResponse::update_connection_state(HTTPRequest& http_request) {
	int res = RESULT_NOT_DEFINED;
	std::string connection_state = http_request.get_header_value("Connection", 0);
	if (connection_state == "close") {
		HTTPResponse::set_header_value("Connection", "close");
		res = RESULT_SUCCESS;
	}
	else if (connection_state == "keep-alive") {
		HTTPResponse::set_header_value("Connection", "keep-alive");
		res = RESULT_SUCCESS;
	}
	else {
		std::cerr << "Unsupported Connection State: " << connection_state << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}

// Response
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