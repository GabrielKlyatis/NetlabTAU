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

	handshakeProtocol.handshake.body.certificate.certificate_list.resize(10);

	for (int i = 0; i < 10; i++) {
		handshakeProtocol.handshake.body.certificate.certificate_list[i].resize(10);
		for (int j = 0; j < 10; j++) {
			handshakeProtocol.handshake.body.certificate.certificate_list[i][j] = 0x45;
		}
	}

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);
	
	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_SERVER_KEY_EXCHANGE_DH_ANON) {

	HandshakeType msg_type = SERVER_KEY_EXCHANGE;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.serverKeyExchange.key_exchange_algorithm = DH_ANON;
	handshakeProtocol.handshake.body.serverKeyExchange.createServerKeyExchange();
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p = { 0x45, 0x45, 0x45, 0x45 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g = { 0x46, 0x46, 0x46, 0x46 };
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.resize(4);
	handshakeProtocol.handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys = { 0x47, 0x47, 0x47, 0x47 };

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_SERVER_KEY_EXCHANGE_DHE_RSA) {

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

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CERTIFICATE_REQUEST) {

	HandshakeType msg_type = CERTIFICATE_REQUEST;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.certificateRequest.certificate_types.resize(4);
	handshakeProtocol.handshake.body.certificateRequest.certificate_types = { RSA_SIGN, DSS_SIGN, FIXED_DH, DSS_FIXED_DH, RSA_EPHEMERAL_DH_RESERVED };
	handshakeProtocol.handshake.body.certificateRequest.certificate_authorities.resize(4);
	
	for (int i = 0; i < 4; i++) {
		handshakeProtocol.handshake.body.certificateRequest.certificate_authorities[i].resize(50);
	}

	std::string authority_str = "C=US, O=VeriSign, Inc., OU=Class 3 Public Primary Certification Authority";
	DistinguishedName authority(authority_str.begin(), authority_str.end());

	handshakeProtocol.handshake.body.certificateRequest.certificate_authorities.push_back(authority);

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CERTIFICATE_VERIFY) {

	HandshakeType msg_type = CERTIFICATE_VERIFY;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);
	
	handshakeProtocol.handshake.body.certificateVerify.digitally_signed.handshake_messages.resize(4);

	for (int i = 0; i < 4; i++) {
		handshakeProtocol.handshake.body.certificateVerify.digitally_signed.handshake_messages.push_back(0x45);
	}

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CLIENT_KEY_EXCHANGE_DH_RSA) {

	HandshakeType msg_type = CLIENT_KEY_EXCHANGE;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.clientKeyExchange.key_exchange_algorithm = DH_RSA;
	handshakeProtocol.handshake.body.clientKeyExchange.createClientKeyExchange();
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major = 0x03;
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor = 0x03;
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>();

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_CLIENT_KEY_EXCHANGE_DH_ANON) {

	HandshakeType msg_type = CLIENT_KEY_EXCHANGE;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.clientKeyExchange.key_exchange_algorithm = DH_ANON;
	handshakeProtocol.handshake.body.clientKeyExchange.createClientKeyExchange();
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding = EXPLICIT;
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.createClientDiffieHellmanPublic();
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.resize(4);
	handshakeProtocol.handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc = { 0x45, 0x45, 0x45, 0x45 };

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}

TEST_F(TLS_Tests, Serialization_Deserialization_Test_FINISHED) {

	HandshakeType msg_type = FINISHED;

	TLSHandshakeProtocol handshakeProtocol;

	handshakeProtocol.handshake.updateBody(msg_type);

	handshakeProtocol.handshake.body.finished.verify_data.resize(4);

	for (int i = 0; i < 4; i++) {
		handshakeProtocol.handshake.body.finished.verify_data.push_back(0x45);
	}

	std::string serialized_string = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	handshakeProtocol.deserialize_handshake_protocol_data(serialized_string, msg_type);

	std::string serialized_string_2 = handshakeProtocol.serialize_handshake_protocol_data(msg_type);

	ASSERT_EQ(serialized_string, serialized_string_2);

	handshakeProtocol.~TLSHandshakeProtocol();
}