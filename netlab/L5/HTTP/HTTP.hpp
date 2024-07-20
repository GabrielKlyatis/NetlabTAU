#pragma once

#include "../L5.h"
#include "../tls_socket.h"

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <map>
#include <sstream>
#include <unordered_map>
#include <functional>


namespace netlab {

/************************************************************************/
/*                               #define                                */
/************************************************************************/

#define R_N_OFFSET 2

/************************************************************************/
/*                             typedefs                                 */
/************************************************************************/


/************************************************************************/
/*								aliases                                 */
/************************************************************************/

	using HTTPHeaders = std::multimap<std::string, std::string>; // Header Name, Header Value
	using QueryParams = std::multimap<std::string, std::string>; // Parameter Name, Parameter Value

	struct HTTPResponse; // Forward Declaration
	using ResponseHandler = std::function<bool(const HTTPResponse& response)>; // Response Callback

/************************************************************************/
/*								 enums			   				        */
/************************************************************************/

	enum HTTPProtocol : uint8_t {
		HTTP,
		HTTPS
	};

	enum HTTPContentType : uint8_t {
		TEXT_PLAIN,
		TEXT_HTML,
		TEXT_CSS,
		TEXT_JAVASCRIPT,
		TEXT_XML,
		IMAGE_JPEG,
		IMAGE_PNG,
		IMAGE_GIF,
		IMAGE_BMP,
		IMAGE_SVG,
		APPLICATION_JSON,
		APPLICATION_XML,
		APPLICATION_PDF,
		APPLICATION_ZIP,
		APPLICATION_OCTET_STREAM,
	};

	enum Header : uint8_t {

		// Request Headers
		Host,
		UserAgent,
		Accept,
		AcceptEncoding,

		// Response Headers
		Date,
		Server,
		CacheControl,
		Expires,
		ContentEncoding,

		// Both
		HTTPContentType,
		ContentLength,
		Connection
	};

	enum StatusCode : uint32_t {

		// Information Responses
		Continue = 100,
		SwitchingProtocols = 101,
		Processing = 102,
		EarlyHints = 103,

		// Successful Responses
		OK = 200,
		Created = 201,
		Accepted = 202,
		NonAuthoritativeInformation = 203,
		NoContent = 204,
		ResetContent = 205,
		PartialContent = 206,
		MultiStatus = 207,
		AlreadyReported = 208,
		IMUsed = 226,

		// Redirection Messages
		MultipleChoices = 300,
		MovedPermanently = 301,
		Found = 302,
		SeeOther = 303,
		NotModified = 304,
		UseProxy = 305,
		Unused = 306,
		TemporaryRedirect = 307,
		PermanentRedirect = 308,

		// Client Error Responses
		BadRequest = 400,
		Unauthorized = 401,
		PaymentRequired = 402,
		Forbidden = 403,
		NotFound = 404,
		MethodNotAllowed = 405,
		NotAcceptable = 406,

		// Server Error Responses
		InternalServerError = 500,
		NotImplemented = 501,
		BadGateway = 502,
		ServiceUnavailable = 503,
		GatewayTimeout = 504,
		HTTPVersionNotSupported = 505,
		VariantAlsoNegotiates = 506,
		InsufficientStorage = 507,
		LoopDetected = 508,
		NotExtended = 510,
		NetworkAuthenticationRequired = 511,
	};

/************************************************************************/
/*                             structs                                  */
/************************************************************************/

	struct Resource {
		std::string uri;
		std::string file_name;
		std::string content;
		std::string content_type;
	};

/************************************************************************/
/*                             classes                                  */
/************************************************************************/
	
/***************************** Request **********************************/
	class HTTPRequest {
	public:
		std::string request_method; // GET | POST
		std::string request_uri; // URI - Uniform Resource Identifier
		std::string request_version = "HTTP/1.1"; // HTTP Version
		HTTPHeaders headers; // Header Name, Header Value
		std::vector<std::string> headers_order; // Order of Headers
		QueryParams query_params; // Query Parameter Name, Query Parameter Value
		std::string body; // Request Body

		// HTTPHeaders
		bool HTTPRequest::has_header(const std::string& key);
		std::string get_header_value(const std::string& key, size_t id);
		uint64_t get_header_value_u64(const std::string& key, size_t id);
		void set_header(const std::string& key, const std::string& val);
		void parse_headers(const std::vector<std::string>& lines);
		std::string to_string();

		// QueryParams
		bool has_param(const std::string& key);
		std::string get_param_value(const std::string& key, size_t id);
		void set_param(const std::string& key, const std::string& val);
		QueryParams parse_query_params(const std::string& query);

		// Request
		void parse_request(const std::string& request_string);
	};
/***************************** Response **********************************/
	class HTTPResponse {
	public:
		std::string version = "HTTP/1.1"; // HTTP Version
		StatusCode status_code; // e.g. - 200, 404, 400, 401, 403, 500
		std::string reason; // e.g. - OK, Not Found, Bad Request, Unauthorized, Forbidden, Internal Server Error
		HTTPHeaders headers; // Header Name, Header Value
		std::vector<std::string> headers_order; // Order of Headers
		std::string body; // Response Body
		std::string location; // Redirect Location

		// HTTPHeaders
		bool has_header(const std::string& key);
		std::string get_header_value(const std::string& key, size_t id);
		uint64_t get_header_value_u64(const std::string& key, size_t id);
		void set_header(const std::string& key, const std::string& val);

		void set_redirect(const std::string& url, int status = StatusCode::Found);
		void set_content(const char* s, size_t n, const std::string& content_type);
		void set_content(const std::string& s, const std::string& content_type);
		void set_content(std::string&& s, const std::string& content_type);

	};

} // namespace netlab