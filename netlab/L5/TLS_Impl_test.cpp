#include "pch.h"
#include "../../netlab/L5/tls_definition.hpp"
#include "../../netlab/L5/tls_implementation.hpp"

using namespace netlab;

class TLS_Tests : public testing::Test {
public:
	//ChangeCipherSpec changeCipherSpec;
	//TLSAlertProtocol alert;
	
};

TEST_F(TLS_Tests, Serialization_Deserialization_Test) {

	HandshakeType msg_type = CERTIFICATE_REQUEST;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.set_handshake(msg_type);

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}