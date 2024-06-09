#include "pch.h"
#include "../../netlab/L5/tls_definition.hpp"
#include "../../netlab/L5/tls_protocol_layer.hpp"

using namespace netlab;

class TLS_Tests : public testing::Test {
public:
	
};

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CLIENT_HELLO) {

	HandshakeType msg_type = CLIENT_HELLO;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.clientHello.setClientHello();

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_SERVER_HELLO) {

	HandshakeType msg_type = SERVER_HELLO;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.serverHello.setServerHello();

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CERTIFICATE) {

	HandshakeType msg_type = CERTIFICATE;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	//handshakeProtocol.handshake.body.certificate.certificate_list.resize(10);

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);
	
	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_SERVER_KEY_EXCHANGE) {

	HandshakeType msg_type = SERVER_KEY_EXCHANGE;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.serverKeyExchange.key_exchange_algorithm = DHE_RSA;
	handshakeProtocol.handshake.body.serverKeyExchange.createServerKeyExchange();
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p = { 0x45, 0x45, 0x45, 0x45 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g = { 0x46, 0x46, 0x46, 0x46 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys = { 0x47, 0x47, 0x47, 0x47 };

	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.gmt_unix_time = static_cast<uint32_t>(time(0));
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes = generate_random_bytes<28>();
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.gmt_unix_time = static_cast<uint32_t>(time(0));
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes = generate_random_bytes<28>();
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p = { 0x48, 0x48, 0x48, 0x48 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g = { 0x49, 0x49, 0x49, 0x49 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys = { 0x50, 0x50, 0x50, 0x50 };

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}