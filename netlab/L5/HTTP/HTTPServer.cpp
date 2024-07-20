#include "HTTPServer.hpp"

namespace netlab {

    bool HTTPServer::has_resource(std::string request_uri) {
    for (auto& resource : resources) {
        if (resource.uri == request_uri) {
            return true;
        }
    }
    return false;
    }

} // namespace netlab