#include "HTTPClient_Impl.hpp"
#include "HTTPServer_Impl.hpp"
#include "../../L1/NIC.h"

using namespace netlab;

/**********************************************************************************************/
/*								      Utility Functions								          */
/**********************************************************************************************/

std::string netlab::create_query_string(QueryParams& params) {
	std::string query_string = "?";
	bool first = true;

	for (const auto& param : params) {
		if (!first) {
			query_string += "&";
		}
		query_string += param.first + "=" + param.second;
		first = false;
	}

	return query_string;
}

std::string netlab::create_headers_string(HTTPHeaders& headers) {
	std::string headers_string;
	std::vector<std::string> default_request_headers_order = { "Host" ,"User-Agent", "Connection", "Content-Type", "Content-Length" };

	for (const auto& header_name : default_request_headers_order) {
		auto it = headers.find(header_name);
		if (it != headers.end()) {
			std::string header_value = it->second;
			headers_string += header_name + ": " + header_value + "\r\n";
		}
	}

	for (const auto& header : headers) {
		if (std::find(default_request_headers_order.begin(), default_request_headers_order.end(), header.first) == default_request_headers_order.end()) {
			std::string header_value = header.second;
			headers_string += header.first + ": " + header_value + "\r\n";
		}
	}

	return headers_string;
}

std::string netlab::get_current_time() {
	std::time_t now = std::time(nullptr);
	char buf[100];
	std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now));
	return std::string(buf);
}

std::vector<std::string> netlab::split_lines(const std::string& str) {
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

std::string netlab::get_user_agent() {
	HKEY hKey;
	char value[255];
	DWORD bufferSize = sizeof(value);
	std::string user_agent = "Unknown";

	// Open the registry key
	if (RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueExA(hKey, "User Agent", NULL, NULL, (LPBYTE)&value, &bufferSize) == ERROR_SUCCESS) {
			user_agent = std::string(value);
		}
		RegCloseKey(hKey);
	}

	return user_agent;
}

// Function to serialize data as application/x-www-form-urlencoded
std::string netlab::serialize_urlencoded(const QueryParams& params) {
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
std::string netlab::serialize_multipart(const QueryParams& params, const std::string& boundary) {
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
std::string netlab::serialize_body(const QueryParams& params, const std::string& content_type) {
	if (content_type == "application/x-www-form-urlencoded") {
		return serialize_urlencoded(params);
	}
	else if (content_type.find("multipart/form-data") != std::string::npos) {
		// Try to extract the boundary from the content_type
		std::string boundary = extract_boundary(content_type);

		// If no boundary was provided, generating a default one
		if (boundary.empty()) {
			boundary = BOUNDARY;
		}

		// Pass the boundary to the serialization function
		return serialize_multipart(params, boundary);
	}
	else {
		std::cerr << "Unsupported Content-Type: " << content_type << std::endl;
		return "";
	}
}

std::string netlab::extract_boundary(const std::string & content_type) {
	std::string boundary = "";
	std::string boundary_prefix = "boundary=";

	// Find the boundary in the content-type
	std::size_t boundary_pos = content_type.find(boundary_prefix);
	if (boundary_pos != std::string::npos) {
		// Extract the boundary value
		boundary = content_type.substr(boundary_pos + boundary_prefix.length());
	}

	return boundary;
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
			if (field_name == "Host" || field_name == "User-Agent" || field_name == "Content-Type" 
				|| field_name == "Content-Length" || field_name == "Connection" || "Content-Disposition") {
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

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> POST BELOW <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

// Body

void HTTPRequest::insert_body_param(const std::string& key, const std::string& val) {
	body_params.emplace(key, val);
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
	body = strippedBody;
}

// Function to parse multipart/form-data
std::string HTTPRequest::parse_multipart(const std::string& body, const std::string& boundary) {
	std::string delimiter = "--" + boundary;
	std::string end_delimiter = delimiter + "--";
	size_t pos = 0, end_pos = 0;

	// Loop through all parts until the end boundary is found
	while ((pos = body.find(delimiter, pos)) != std::string::npos) {
		pos += delimiter.length() + 2; // Delimiter and \r\n

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
            parse_headers(split_lines(headers));
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
                    return content;
				}
			}
		}
	}
	return nullptr;
}

// Main function to parse the body - returns raw body
std::string HTTPRequest::parse_body(const std::string & body, const std::string & content_type) {
	std::string raw_body = body;
	if (content_type == "application/x-www-form-urlencoded") {
		std::string body_copy = body;  // Make a copy because regex modifies the string
		parse_urlencoded(body_copy);
	}
	else if (content_type.find("multipart/form-") != std::string::npos) {
		// Extract boundary from content_type
		size_t boundary_pos = content_type.find("boundary=");
		if (boundary_pos != std::string::npos) {
			std::string boundary = content_type.substr(boundary_pos + 9);  // Skip 'boundary='
			raw_body = parse_multipart(body, boundary);
		}
	}
	else {
		std::cerr << "Unsupported Content-Type: " << content_type << std::endl;
		return nullptr;
	}
	return raw_body;
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> POST ABOVE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< //

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
				field_name == "Content-Length" || field_name == "Connection") {
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


/**********************************************************************************************/
/* HTTP Client & Server Utility Functions - Given but implementation is invisible to students */
/**********************************************************************************************/

void HTTPClient_Impl::connect_to_server(inet_os& inet_server, HTTPServer_Impl* http_server) {

	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_server.nic()->ip_addr().s_addr;
	clientService.sin_port = protocol == HTTPProtocol::HTTP ? htons(SERVER_PORT) : htons(SERVER_PORT_HTTPS);

	netlab::L5_socket* connectSocket = socket;
	std::thread([connectSocket, clientService]()
		{
			connectSocket->connect((SOCKADDR*)&clientService, sizeof(clientService));
		}).detach();
}

Resource* HTTPClient_Impl::get_resource(std::string& uri) {
	for (Resource& resource : resources_from_server) {
		if (resource.file_name == SERVER_FILESYSTEM + uri) {
			return &resource;
		}
	}
	std::cerr << "Failed to obtain the requested resource." << std::endl;
	return nullptr;
}

void HTTPServer_Impl::listen_for_connection() {

	sockaddr_in serverService;
	serverService.sin_family = AF_INET;
	serverService.sin_addr.s_addr = INADDR_ANY;
	serverService.sin_port = protocol == HTTPProtocol::HTTP ? htons(SERVER_PORT) : htons(SERVER_PORT_HTTPS);

	socket->bind((SOCKADDR*)&serverService, sizeof(serverService));
	socket->listen(5);
}

void HTTPServer_Impl::run_server(inet_os& inet_server, HTTPProtocol http_protocol) {
	
	std::cout << "HTTPS Server is running..." << std::endl << std::endl;

	set_HTTP_procotol(http_protocol, inet_server);
	listen_for_connection();

	std::thread serverThread([this, &inet_server]() {
		while (true) {
			if (socket) {
				client_socket = socket->accept(nullptr, 0);
				std::cout << "Client connected" << std::endl;
				if (protocol == HTTPProtocol::HTTPS) {
					netlab::tls_socket* tls_sock = (new netlab::tls_socket(inet_server, client_socket, true));
					tls_sock->handshake();
					client_socket = tls_sock;
				}
			}
			if (client_socket) {
				// Receive the GET request
				std::string received_request;
				client_socket->recv(received_request, SB_SIZE_DEFAULT, 1, 0);
				process_request(received_request);

				// Close the connection
				client_socket->shutdown(SD_RECEIVE);
				client_socket = nullptr;
			}
		}
	});

	std::this_thread::sleep_for(std::chrono::seconds(1));
	serverThread.detach();
}

// Check if the server has the requested resource
bool HTTPServer_Impl::has_resource(std::string& request_path) {
	bool file_exists = false;
	std::string full_path = SERVER_FILESYSTEM + request_path;
	std::ifstream file(full_path);
	file_exists = file.good();
	file.close();
	return file_exists;
}

// Remove the resource from the server
int HTTPServer_Impl::remove_resource(std::string& request_path) {
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
int HTTPServer_Impl::create_resource(HTTPRequest& HTTP_request) {
	int res = RESULT_SUCCESS;
	std::string full_path = SERVER_FILESYSTEM + HTTP_request.request_uri;
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
	resource_file << HTTP_request.body;
	resource_file.close();
	if (res != RESULT_SUCCESS) {
		std::cerr << "HTTP SERVER: Failed to create resource on the server." << full_path << std::endl;
		res = RESULT_FAILURE;
	}

	if (res != RESULT_FAILURE) {
		Resource resource;
		resource.file_name = SERVER_FILESYSTEM + HTTP_request.request_uri;
		resource.content = HTTP_request.body;
		resource.content_type = HTTP_request.get_header_value("Content-Type", 0);
		resources.push_back(resource);
	}

	return res;
}

// Get the resource from the server
Resource* HTTPServer_Impl::get_resource(std::string& uri) {
	for (Resource& resource : resources) {
		if (resource.file_name == SERVER_FILESYSTEM + uri) {
			return &resource;
		}
	}
	std::cerr << "Failed to obtain the requested resource." << std::endl;
	return nullptr;
}

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

// Send the response to the client
void HTTPServer_Impl::send_response(HTTPResponse& HTTP_response, bool close_connection) {

	// Serialize the response
	std::string response_string = HTTP_response.to_string();
	size_t size = response_string.size();

	// Send the response to the client and close the connection if needed
	client_socket->send(response_string, size, 0, 0);
}