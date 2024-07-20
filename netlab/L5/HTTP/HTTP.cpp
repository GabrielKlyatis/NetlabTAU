#include "HTTP.hpp"

namespace netlab {

/************************************************************************/
/*                               Utils                                  */
/************************************************************************/

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

	std::string status_message(StatusCode status_code) {
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


/************************************************************************/
/*                             Request                                  */
/************************************************************************/

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
	void HTTPRequest::set_header(const std::string& key, const std::string& val) {
		headers.emplace(key, val);
		headers_order.push_back(key);
	}
	void HTTPRequest::parse_headers(const std::vector<std::string>& lines) {
		std::multimap<std::string, std::string> headers;
		for (size_t i = 0; i < lines.size(); ++i) {
			size_t pos = lines[i].find(':');
			if (pos != std::string::npos) {
				std::string field_name = lines[i].substr(0, pos);
				// Check if the header is supported
				if (field_name == "Host" || field_name == "User-Agent" || field_name == "Accept" ||
					field_name == "Content-Type" || field_name == "Content-Length" || field_name == "Accept-Encoding" ||
					field_name == "Connection") {
					std::string field_value = lines[i].substr(pos + 2); // Skip ": " (colon and space)
					set_header(field_name, field_value);
				}
				else {
					std::cout << "Unsupported Header: " << field_name << std::endl;
				}
			}
		}
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
	void HTTPRequest::set_param(const std::string& key, const std::string& val) {
		query_params.emplace(key, val);
	}
	QueryParams HTTPRequest::parse_query_params(const std::string& query) {
		QueryParams query_params;
		std::istringstream query_stream(query);
		std::string pair;
		while (std::getline(query_stream, pair, '&')) {
			size_t pos = pair.find('=');
			if (pos != std::string::npos) {
				std::string key = pair.substr(0, pos);
				std::string value = pair.substr(pos + 1);
				set_param(key, value);
			}
		}
		return query_params;
	}

	// Request
	void HTTPRequest::parse_request(const std::string& request_string) {
		size_t method_end = request_string.find(' ');
		if (method_end != std::string::npos) {
			request_method = request_string.substr(0, method_end); // GET | POST
			size_t uri_end = request_string.find(' ', method_end + 1);
			if (uri_end != std::string::npos) {
				request_uri = request_string.substr(method_end + 1, uri_end - method_end - 1); // URI
				size_t version_end = request_string.find('\r', uri_end + 1);
				if (version_end != std::string::npos) {
					request_version = request_string.substr(uri_end + 1, version_end - uri_end - 1); // HTTP Version
				}
				// Parse Headers
				std::vector<std::string> header_lines = split_lines(request_string.substr(version_end + R_N_OFFSET));
				parse_headers(header_lines); // Header Name, Header Value

				if (request_method == "POST") {
					size_t content_length = get_header_value_u64("Content-Length");
					std::string body_string = request_string.substr(request_string.find("\r\n\r\n") + 2 * R_N_OFFSET);
					if (body_string.size() < content_length) {
						std::cout << "Body size is less than Content-Length" << std::endl;
					}
					else {
						body = body_string.substr(0, content_length);
					}

				}
			}
		}
	}
	std::string HTTPRequest::to_string() {
		std::string request_string = request_method + " " + request_uri + " " + request_version + "\r\n";
		for (auto& header : headers_order) {

			std::string header_value = headers.find(header)->second;
			request_string += header + ": " + header_value + "\r\n";
		}
		request_string += "\r\n";
		if (request_method == "POST") {
			request_string += body;
		}
		return request_string;
	}

/************************************************************************/
/*                             Response                                 */
/************************************************************************/

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
	void HTTPResponse::set_header(const std::string& key, const std::string& val) {
		headers.emplace(key, val);
	}

} // namespace netlab

