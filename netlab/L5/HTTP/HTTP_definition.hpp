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

    enum HTTPMethod {
        GET,
        POST,
    };

    enum HTTPStatusCode {
        OK = 200,
        NotFound = 404,
        BadRequest = 400,
        Unauthorized = 401,
        Forbidden = 403,
        InternalServerError = 500,
        // Add more status codes as needed
    };

/************************************************************************/
/*                             Structs                                  */
/************************************************************************/

    struct HTTPRequest {
        HTTPMethod method;
        std::string uri;
        std::map<std::string, std::string> headers;
        std::string body;
    };

    struct HTTPResponse {
        HTTPStatusCode statusCode;
        std::string reasonPhrase;
        std::map<std::string, std::string> headers;
        std::string body;
    };


} // namespace netlab