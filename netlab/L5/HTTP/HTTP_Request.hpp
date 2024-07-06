#pragma once

#include "../L5.h"

#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <map>

namespace netlab {

	/************************************************************************/
	/*                               #define                                */
	/************************************************************************/


	/************************************************************************/
	/*                             typedefs                                 */
	/************************************************************************/


	 /************************************************************************/
	/*								 enums			   				        */
	/************************************************************************/

	enum HTTPMethod : uint8_t {
		GET,
		POST,
	};

	enum ContentType : uint8_t {
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
		// Add more content types as needed
	};

	enum RequestHeader : uint8_t {
		Cookie,
		Host,
		UserAgent,
		Accept,
		AcceptEncoding,
		Connection
	};

	enum HTTPStatusCode : uint8_t {
		OK = 200,
		NotFound = 404,
		BadRequest = 400,
		Unauthorized = 401,
		Forbidden = 403,
		InternalServerError = 500,
	};

	/************************************************************************/
	/*                             Structs                                  */
	/************************************************************************/

	struct HTTPDate {
		uint16_t day;
		uint16_t month;
		uint16_t year;
		uint16_t hour;
		uint16_t minute;
		uint16_t second;
		std::string timezone;
	};


	struct HTTPRequest {
		HTTPMethod method; // GET / POST
		std::string uri; // Uniform Resource Identifier (URL)
		std::map<RequestHeader, std::string> headers;
		std::string body;
	};


} // namespace netlab