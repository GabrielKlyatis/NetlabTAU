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

/**********************************************************************************************/
/*											Request								              */
/**********************************************************************************************/

	// Constructor
HTTPRequest::HTTPRequest() : request_method(""), request_uri(""), request_path(""),
request_version("HTTP/1.1"), headers(default_request_headers),
headers_order(default_request_headers_order), body("") {}

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
	headers_order.push_back(key);
}
int HTTPRequest::parse_headers(const std::vector<std::string>& lines) {
	int res = RESULT_NOT_DEFINED;
	for (size_t i = 0; i < lines.size(); ++i) {
		size_t pos = lines[i].find(':');
		if (pos != std::string::npos) {
			std::string field_name = lines[i].substr(0, pos);
			// Check if the header is supported
			if (field_name == "Host" || field_name == "User-Agent" || field_name == "Accept" ||
				field_name == "Content-Type" || field_name == "Content-Length" || field_name == "Accept-Encoding" ||
				field_name == "Connection") {
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

// Body
void HTTPRequest::insert_body_param(const std::string& key, const std::string& val) {
	body_params.emplace(key, val);
}
void HTTPRequest::parse_body_query_params(std::string& unfiltered_body) {
	std::string strippedBody = unfiltered_body;
	std::regex keyValuePairRegex(R"((^|[&\s])([^&=]+)=([^&\s]*)(?=(&|\s|$)))");
	std::smatch match;

	// Remove all key-value pairs
	while (std::regex_search(strippedBody, match, keyValuePairRegex)) {
		// Insert the matched key-value pair into the query_params map
		insert_body_param(match[2].str(), match[3].str());
		// Remove the matched key-value pair from the string
		strippedBody = match.prefix().str() + match.suffix().str();
	}
}

// Request
int HTTPRequest::parse_request(const std::string& request_string) {
	int res = RESULT_NOT_DEFINED;
	// Parse Method
	size_t method_end = request_string.find(' ');
	if (method_end != std::string::npos) {
		request_method = request_string.substr(0, method_end); // GET | POST
		size_t uri_end = request_string.find(' ', method_end + 1);
		if (uri_end != std::string::npos) {
			// Parse URI
			request_uri = request_string.substr(method_end + 1, uri_end - method_end - 1); // URI
			// Parse Query Parameters
			size_t query_start = request_uri.find('?');
			if (query_start != std::string::npos) {
				parse_query_params(request_uri.substr(query_start + 1));
				// Parse Path
				request_path = request_uri.substr(0, query_start);
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
				res = RESULT_FAILURE;
				return res;
			}
			// In the case of POST, parse the body
			if (request_method == "POST") {
				size_t content_length = get_header_value_u64("Content-Length");
				std::string unfiltered_body_string = request_string.substr(request_string.find("\r\n\r\n") + 2 * R_N_OFFSET);
				if (unfiltered_body_string.size() < content_length) {
					std::cout << "Body size is less than Content-Length" << std::endl;
				}
				else {
					// Parse the body and update the body_params
					parse_body_query_params(unfiltered_body_string);
					body = unfiltered_body_string;
				}
			}
		}
	}
	if (res != RESULT_SUCCESS) {
		std::cerr << "Failed to parse the request." << std::endl;
		res = RESULT_FAILURE;
	}
	return res;
}
std::string HTTPRequest::to_string() {
	std::string request_string = "";
	// No query parameters - simple request
	request_string += request_method + " " + request_uri + " " + request_version + "\r\n";
	// Serialize the headers
	for (auto& header : headers_order) {
		std::string header_value = headers.find(header)->second;
		request_string += header + ": " + header_value + "\r\n";
	}
	request_string += "\r\n";
	// Serialize the body (if any)
	if (request_method == "POST") {
		request_string += body;
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
	parse_response(response_string);
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
	headers_order.push_back(key);
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

