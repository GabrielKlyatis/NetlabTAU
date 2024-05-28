#include "tls_definition.hpp"
#include "tls_implementation.hpp"

using namespace netlab;

void main() {

	ChangeCipherSpec changeCipherSpec;
	TLSAlertProtocol alert;
	TLSHandshakeProtocol handshakeProtocol;

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(CLIENT_HELLO);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, CLIENT_HELLO);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(CLIENT_HELLO);
	
	if (serialized_string == serialized_string_2) {
		std::cout << "Serialization and Deserialization of Handshake Protocol is successful" << std::endl;
	}
	else {
		std::cout << "Serialization and Deserialization of Handshake Protocol is not successful" << std::endl;
	}
}
