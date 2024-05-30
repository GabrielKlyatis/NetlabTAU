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

	TLSHandshakeProtocol handshakeProtocol(CLIENT_HELLO);

	handshakeProtocol.handshake.body.clientHello.random.gmt_unix_time = time(0);
	handshakeProtocol.handshake.body.clientHello.random.random_bytes = handshakeProtocol.generate_random_bytes<28>();
	handshakeProtocol.handshake.body.clientHello.session_id = handshakeProtocol.generate_random_bytes<32>();

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(CLIENT_HELLO);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, CLIENT_HELLO);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(CLIENT_HELLO);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}