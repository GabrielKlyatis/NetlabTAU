#pragma once

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <map>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <regex>
#include <fstream>
#include <ctime>
#include <Windows.h>

#include "../L5.h"
#include "../tls_socket.h"

namespace netlab {

/************************************************************************/
/*                               #define                                */
/************************************************************************/

#define SERVER_PORT 8888
#define SERVER_PORT_HTTPS 4433
#define CLIENT_PORT 5000
#define RESULT_NOT_DEFINED -1
#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1
#define R_N_OFFSET 2
#define SERVER_FILESYSTEM "L5/HTTP/Server_filesystem"
#define CLIENT_HARD_DRIVE "L5/HTTP/Client_HD" 
#define BOUNDARY "inet_os_boundary"
#define G_CHROME "GoogleChromePortable\\GoogleChromePortable.exe"

/************************************************************************/
/*								aliases                                 */
/************************************************************************/

	using HTTPHeaders = std::multimap<std::string, std::string>; // Header Name, Header Value
	using QueryParams = std::multimap<std::string, std::string>; // Parameter Name, Parameter Value

/************************************************************************/
/*							  constants					                */
/************************************************************************/

	const HTTPHeaders default_request_headers = {
	{"Host", ""},
	{"User-Agent", ""},
	{"Connection", ""},
	{"Content-Type", ""},
	{"Content-Length", "0"},
	};

	const std::vector<std::string> default_request_headers_order = {
		"Host",
		"User-Agent",
		"Connection",
		"Content-Type",
		"Content-Length"
	};

	const HTTPHeaders default_response_headers = {
	{"Server", "inet_os_HTTP/1.1"},
	{"Date", ""},
	{"Content-Type", ""},
	{"Content-Length", "0"},
	{"Connection", ""},
	};

	const std::vector<std::string> default_response_headers_order = {
		"Server",
		"Date",
		"Content-Type",
		"Content-Length",
		"Connection",
	};

/************************************************************************/
/*								 enums			   				        */
/************************************************************************/

	enum HTTPProtocol : uint8_t {
		HTTP,
		HTTPS
	};

	enum HTTPMethod : uint8_t {
		GET,
		POST
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
/*                        Utility Functions                             */
/************************************************************************/

	std::vector<std::string> split_lines(const std::string& str);
	std::string create_query_string(QueryParams& params);
	std::string create_headers_string(HTTPHeaders& headers);
	std::string get_current_time();
	std::string get_content_type(std::string& resource_path);
	std::string get_file_contents(const std::string& resource_path);
	std::string url_decode(const std::string& str);
	std::string get_user_agent();

	// Body functions (POST)
	std::string serialize_urlencoded(const QueryParams& params);
	std::string serialize_multipart(const QueryParams& params, const std::string& boundary);
	std::string serialize_body(const QueryParams& params, const std::string& content_type);
	std::string extract_boundary(const std::string& content_type);

/************************************************************************/
/*                             structs                                  */
/************************************************************************/

	struct Resource {
		std::string file_name;
		std::string content;
		std::string content_type;
	};

/************************************************************************/
/*                             classes                                  */
/************************************************************************/

/************************************************************************/
/***************************** Request **********************************/
	class HTTPRequest {
	public:
		std::string request_method; // GET | POST
		std::string request_uri; // URI - Uniform Resource Identifier
		std::string request_path; // Path
		std::string request_version; // HTTP Version
		HTTPHeaders headers; // Header Name, Header Value
		std::vector<std::string> headers_order; // Order of Headers
		QueryParams query_params; // Query Parameter Name, Query Parameter Value
		std::string body; // Request Body
		QueryParams body_params; // Body Parameter Name, Body Parameter Value

		// Constructor
		HTTPRequest();
		HTTPRequest(const std::string& request_string);

		// HTTPHeaders
		bool has_header(const std::string& key);
		std::string get_header_value(const std::string& key, size_t id);
		uint64_t get_header_value_u64(const std::string& key, size_t id);
		void set_header_value(const std::string& key, const std::string& val);
		void insert_header(const std::string& key, const std::string& val);
		int parse_headers(const std::vector<std::string>& lines);
		
		// QueryParams
		bool has_param(const std::string& key);
		std::string get_param_value(const std::string& key, size_t id);
		void insert_param(const std::string& key, const std::string& val);
		void parse_query_params(const std::string& query);

		// Body
		void insert_body_param(const std::string& key, const std::string& val);
		void parse_urlencoded(std::string& unfiltered_body);
		std::string parse_multipart(const std::string& body, const std::string& boundary);
		std::string parse_body(const std::string& body, const std::string& content_type);

		// Request
		int parse_request(const std::string& request_string);
		std::string to_string();
	};

/*************************************************************************/
/***************************** Response **********************************/
	class HTTPResponse {
	public:
		std::string version; // HTTP Version
		StatusCode status_code; // e.g. - 200, 404, 400, 401, 403, 500
		std::string reason; // e.g. - OK, Not Found, Bad Request, Unauthorized, Forbidden, Internal Server Error
		HTTPHeaders headers; // Header Name, Header Value
		std::vector<std::string> headers_order; // Order of Headers
		std::string body; // Response Body

		// Constructor
		HTTPResponse();
		HTTPResponse::HTTPResponse(const std::string& response_string);

		// Status
		static std::string status_message(StatusCode status_code);

		// HTTPHeaders
		bool has_header(const std::string& key);
		std::string get_header_value(const std::string& key, size_t id);
		uint64_t get_header_value_u64(const std::string& key, size_t id);
		void set_header_value(const std::string& key, const std::string& val);
		void insert_header(const std::string& key, const std::string& val);
		int parse_headers(const std::vector<std::string>& lines);
		int update_connection_state(HTTPRequest& http_request);

		// Response
		int parse_response(const std::string& response_string);
		std::string to_string();
	};
} // namespace netlab