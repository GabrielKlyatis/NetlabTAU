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
	};

    enum ResponseHeader : uint8_t {
		Date,
		Expires,
		CacheControl,
		ContentType,
		ContentEncoding,
		Server,
		ContentLength,
		X_XSS_Protection,
		X_Frame_Options,
		Set_Cookie,
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


    struct HTTPResponse {
        HTTPStatusCode statusCode; // 200, 404, 400, 401, 403, 500
        std::string reasonPhrase; // OK, Not Found, Bad Request, Unauthorized, Forbidden, Internal Server Error
        std::map<ResponseHeader, std::string> headers;
        std::string body;
    };


} // namespace netlab