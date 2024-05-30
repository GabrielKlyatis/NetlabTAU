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

	HandshakeType msg_type = SERVER_HELLO;

	TLSHandshakeProtocol handshakeProtocol(msg_type);

	uint32_t current_time = static_cast<uint32_t>(time(0));
	handshakeProtocol.handshake.body.serverHello.random.gmt_unix_time = current_time;
	handshakeProtocol.handshake.body.serverHello.random.random_bytes = handshakeProtocol.generate_random_bytes<28>();
	handshakeProtocol.handshake.body.serverHello.session_id = handshakeProtocol.generate_random_bytes<32>();

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}