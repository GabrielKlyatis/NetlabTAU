#include "tls_protocol_layer.hpp"

using namespace netlab;

/************************************************************************/
/*                         TLS Record Layer                             */
/************************************************************************/

std::string TLSRecordLayer::serialize_record_layer_data() {

	std::string serialized_string;
	// Serialize the record layer's content type and protocol version.
	serialized_string.push_back(this->content_type);
	serialized_string.push_back(this->protocol_version.major);
	serialized_string.push_back(this->protocol_version.minor);
	// Serialize the record layer's length.
	serialize_2_bytes(serialized_string, this->length);
	// Serialize the fragment (if it exists).
	if (fragment.size() > 0) {
		serialized_string.push_back(static_cast<char>(fragment.size()));
		serialized_string.insert(serialized_string.end(),
			this->fragment.begin(),
			this->fragment.end());
	}

	return serialized_string;
}

void TLSRecordLayer::deserialize_record_layer_data(std::string::const_iterator& it, const std::string& serialized_string) {

	// Deserialize the record layer's content type.
	this->content_type = static_cast<ContentType>(*it);
	it += sizeof(ContentType);
	// Deserialize the record layer's protocol version.
	this->protocol_version.major = *it;
	it++;
	this->protocol_version.minor = *it;
	it++;
	// Deserialize the record layer's length.
	this->length = deserialize_2_bytes(it);
}

/************************************************************************/
/*                      Change Cipher Specs Message                     */
/************************************************************************/

std::string ChangeCipherSpec::serialize_change_cipher_spec_data() {

	std::string serialized_string;
	// Record Layer
	serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
	// ChangeCipherSpec type.
	serialized_string.push_back(type);

	return serialized_string;
}

void ChangeCipherSpec::deserialize_change_cipher_spec_data(std::string serialized_string) {

	std::string::const_iterator it = serialized_string.begin();
	// Record Layer
	this->TLS_record_layer.deserialize_record_layer_data(it, serialized_string);
	// ChangeCipherSpec type.
	this->type = static_cast<Type>(*it);
}

/************************************************************************/
/*                       TLS Handshake Protocol							*/
/************************************************************************/

void TLSHandshakeProtocol::updateHandshakeProtocol(HandshakeType msg_type) {

	this->TLS_record_layer.content_type = TLS_CONTENT_TYPE_HANDSHAKE;
	switch (msg_type) {
	case CLIENT_HELLO:
		this->handshake.updateHandshakeLength(msg_type);
		this->TLS_record_layer.protocol_version.major = 3;
		this->TLS_record_layer.protocol_version.minor = 1;
		this->TLS_record_layer.length = this->handshake.length + HANDSHAKE_RECORD_LAYER_OFFSET_LENGTH;
		break;
	case SERVER_HELLO:
		this->handshake.updateHandshakeLength(msg_type);
		this->TLS_record_layer.length = this->handshake.length + HANDSHAKE_RECORD_LAYER_OFFSET_LENGTH;
		break;
	case CERTIFICATE:
		this->handshake.updateHandshakeLength(msg_type);
		this->TLS_record_layer.length = this->handshake.length + HANDSHAKE_RECORD_LAYER_OFFSET_LENGTH;
	case SERVER_KEY_EXCHANGE:
		break;
	case CERTIFICATE_REQUEST:
		break;
	case SERVER_HELLO_DONE:
		this->handshake.updateHandshakeLength(msg_type);
		this->TLS_record_layer.length = SERVER_DONE_RECORD_LAYER_LENGTH;
		break;
	case CERTIFICATE_VERIFY:
		break;
	case CLIENT_KEY_EXCHANGE:
		this->handshake.updateHandshakeLength(msg_type);
		this->TLS_record_layer.length = this->handshake.length + HANDSHAKE_RECORD_LAYER_OFFSET_LENGTH;
		break;
	case FINISHED:
		break;
	default:
		break;
	}
}

std::string TLSHandshakeProtocol::serialize_handshake_protocol_data(HandshakeType msg_type) {

	KeyExchangeAlgorithm clientKeyExchangeAlgorithm;
	KeyExchangeAlgorithm serverKeyExchangeAlgorithm;
	PublicValueEncoding publicValueEncoding;

	/*********************************************************************************************/

	std::string serialized_string;

	// Serialize the handshake's body based on the message type.
	switch (msg_type) {
	case CLIENT_HELLO:
		// Handshake's Record Layer
		serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
		// HandshakeType and its length.
		serialized_string.push_back(this->handshake.msg_type);
		serialize_3_bytes(serialized_string, this->handshake.length);
		// ProtocolVersion
		serialized_string.push_back(this->handshake.body.clientHello->client_version.major);
		serialized_string.push_back(this->handshake.body.clientHello->client_version.minor);
		// Random.gmt_unix_time
		serialize_4_bytes(serialized_string, this->handshake.body.clientHello->random.gmt_unix_time);
		// Random.random_bytes
		serialized_string.insert(serialized_string.end(),
			this->handshake.body.clientHello->random.random_bytes.begin(),
			this->handshake.body.clientHello->random.random_bytes.end());
		// SessionID
		if (is_all_zeros_array(this->handshake.body.clientHello->session_id)) {
			serialized_string.push_back(0);
		}
		else {
			serialized_string.push_back(this->handshake.body.clientHello->session_id.size());
			serialized_string.insert(serialized_string.end(),
				this->handshake.body.clientHello->session_id.begin(),
				this->handshake.body.clientHello->session_id.end());
		}
		// CipherSuites
		serialize_2_bytes(serialized_string, static_cast<uint16_t>(this->handshake.body.clientHello->cipher_suites.size() * sizeof(CipherSuite)));
		for (CipherSuite cipher_suite : this->handshake.body.clientHello->cipher_suites) {
			serialized_string.append(reinterpret_cast<const char*>(cipher_suite.data()), cipher_suite.size());
		}
		// CompressionMethods
		serialized_string.push_back(this->handshake.body.clientHello->compression_methods.size());
		serialized_string.insert(serialized_string.end(),
			this->handshake.body.clientHello->compression_methods.begin(),
			this->handshake.body.clientHello->compression_methods.end());
		// Extensions
		if (this->handshake.body.clientHello->extensions_present) {
			serialized_string.push_back(this->handshake.body.clientHello->extensions_union.extensions.size());
			for (const auto& extension : this->handshake.body.clientHello->extensions_union.extensions) {
				serialized_string.push_back(static_cast<char>(extension.extension_type));
				serialized_string.insert(serialized_string.end(),
					extension.extension_data.begin(),
					extension.extension_data.end());
			}
		}
		else {
			serialize_2_bytes(serialized_string, 0); // Extensions length is 0.
		}
		break;
	case SERVER_HELLO:
		// Handshake's Record Layer
		serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
		// HandshakeType and its length.
		serialized_string.push_back(this->handshake.msg_type);
		serialize_3_bytes(serialized_string, this->handshake.length);
		// ProtocolVersion
		serialized_string.push_back(this->handshake.body.serverHello->server_version.major);
		serialized_string.push_back(this->handshake.body.serverHello->server_version.minor);
		// Random.gmt_unix_time
		serialize_4_bytes(serialized_string, this->handshake.body.serverHello->random.gmt_unix_time);
		// Random.random_bytes
		serialized_string.insert(serialized_string.end(),
			this->handshake.body.serverHello->random.random_bytes.begin(),
			this->handshake.body.serverHello->random.random_bytes.end());
		// SessionID
		if (is_all_zeros_array(this->handshake.body.serverHello->session_id)) {
			serialized_string.push_back(0);
		}
		else {
			serialized_string.push_back(this->handshake.body.serverHello->session_id.size());
			serialized_string.insert(serialized_string.end(),
				this->handshake.body.serverHello->session_id.begin(),
				this->handshake.body.serverHello->session_id.end());
		}
		// CipherSuites
		serialized_string.append(reinterpret_cast<const char*>(this->handshake.body.serverHello->cipher_suite.data()),
			this->handshake.body.serverHello->cipher_suite.size());
		// CompressionMethods
		serialized_string.push_back(this->handshake.body.serverHello->compression_method);
		// Extensions

		if (this->handshake.body.serverHello->extensions_present) {
			uint16_t ext_size = this->handshake.body.serverHello->extensions_union.extensions.size() * this->handshake.body.serverHello->extensions_union.extensions[0].extension_data.size();
			serialize_2_bytes(serialized_string, ext_size);
			for (const auto& extension : this->handshake.body.serverHello->extensions_union.extensions) {
				//serialized_string.push_back(static_cast<char>(extension.extension_type));
				serialized_string.insert(serialized_string.end(),
					extension.extension_data.begin(),
					extension.extension_data.end());
			}
		}
		else {
			serialize_2_bytes(serialized_string, 0); // Extensions length is 0.
		}
		break;
	case CERTIFICATE:
		// Handshake's Record Layer
		serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
		// HandshakeType and its length.
		serialized_string.push_back(this->handshake.msg_type);
		serialize_3_bytes(serialized_string, this->handshake.length);
		// Certificate List.		
		serialize_3_bytes(serialized_string, this->handshake.length - CERTIFICATE_HANDSHAKE_OFFSET_LENGTH);
		for (std::size_t i = 0; i < this->handshake.body.certificate->certificate_list.size(); ++i) {
			std::vector<uint8_t> certificate = this->handshake.body.certificate->certificate_list[i];
			if (!is_all_zeros_vector(certificate)) {
				serialize_3_bytes(serialized_string, certificate.size());
				serialized_string.insert(serialized_string.end(), certificate.begin(), certificate.end());
			}
		}
		break;
	case SERVER_KEY_EXCHANGE:
		serverKeyExchangeAlgorithm = this->handshake.body.serverKeyExchange->key_exchange_algorithm;
		// KeyExchangeAlgorithm
		serialized_string.push_back(this->handshake.body.serverKeyExchange->key_exchange_algorithm);
		switch (serverKeyExchangeAlgorithm) {
		case DH_ANON:
			// DH parameters
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_p.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_p) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_g.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_g) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_Ys.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_Ys) {
				serialized_string.push_back(byte);
			}
			break;
		case DHE_RSA:
			// DH parameters
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_p.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_p) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_g.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_g) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_Ys.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_Ys) {
				serialized_string.push_back(byte);
			}
			// SignedParams.client_random.gmt_unix_time
			for (int i = 0; i < sizeof(uint32_t); ++i) {
				serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange->server_exchange_keys
					.dhe_rsa.signed_params.client_random.gmt_unix_time >> (i * 8)) & 0xFF));
			}
			// SignedParams.client_random.random_bytes
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.size());
			serialized_string.insert(serialized_string.end(),
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.begin(),
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.end());
			// SignedParams.server_random.gmt_unix_time
			for (int i = 0; i < sizeof(uint32_t); ++i) {
				serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange->server_exchange_keys
					.dhe_rsa.signed_params.server_random.gmt_unix_time >> (i * 8)) & 0xFF));
			}
			// SignedParams.server_random.random_bytes
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.size());
			serialized_string.insert(serialized_string.end(),
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.begin(),
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.end());
			// SignedParams.params
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_p.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_p) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_g.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_g) {
				serialized_string.push_back(byte);
			}
			append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.size());
			for (const auto& byte : this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys) {
				serialized_string.push_back(byte);
			}
		}		/********************************************************************************************/
		break;
	case CERTIFICATE_REQUEST:
		// CertificateTypes
		append_size_to_string(serialized_string, this->handshake.body.certificateRequest->certificate_types.size());
		for (const auto& type : this->handshake.body.certificateRequest->certificate_types) {
			serialized_string.push_back(type);
		}
		// CertificateAuthorities
		append_size_to_string(serialized_string, this->handshake.body.certificateRequest->certificate_authorities.size());
		for (const auto& authority : this->handshake.body.certificateRequest->certificate_authorities) {
			for (int j = 0; j < sizeof(uint32_t); ++j) {
				serialized_string.push_back(static_cast<char>((authority.size() >> (j * 8)) & 0xFF));
			}
			serialized_string.insert(serialized_string.end(), authority.begin(), authority.end());
		}
		break;
	case SERVER_HELLO_DONE:
		// Handshake's Record Layer
		serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
		// HandshakeType and its length.
		serialized_string.push_back(this->handshake.msg_type); // HandshakeType = SERVER_HELLO_DONE
		serialize_3_bytes(serialized_string, 0); // Length = 0
		break;
	case CERTIFICATE_VERIFY:
		// DigitallySigned.handshake_messages
		append_size_to_string(serialized_string, this->handshake.body.certificateVerify->digitally_signed.handshake_messages.size());
		serialized_string.insert(serialized_string.end(),
			this->handshake.body.certificateVerify->digitally_signed.handshake_messages.begin(),
			this->handshake.body.certificateVerify->digitally_signed.handshake_messages.end());
		break;
	case CLIENT_KEY_EXCHANGE:
		clientKeyExchangeAlgorithm = this->handshake.body.clientKeyExchange->key_exchange_algorithm;
		publicValueEncoding = this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding;
		// Handshake's Record Layer
		serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());
		// HandshakeType and its length.
		serialized_string.push_back(this->handshake.msg_type);
		serialize_3_bytes(serialized_string, this->handshake.length);
		// KeyExchangeAlgorithm
		switch (clientKeyExchangeAlgorithm) {
		case KEY_EXCHANGE_ALGORITHM_RSA:
			// EncryptedPreMasterSecret.encrypted_pre_master_secret
			serialize_2_bytes(serialized_string,
				this->handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.size());
			serialized_string.insert(serialized_string.end(),
				this->handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.begin(),
				this->handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.end());
			break;
		case DH_ANON:
			// PublicValueEncoding
			serialized_string.push_back(this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding);
			switch (publicValueEncoding) {
			case EXPLICIT:
				// DHPublic.dh_Yc
				append_size_to_string(serialized_string, this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.begin(),
					this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.end());
				break;
			case IMPLICIT:
				break;
			}
			break;
		}
		break;
	case FINISHED:
		// VerifyData
		append_size_to_string(serialized_string, this->handshake.body.finished->verify_data.size());
		serialized_string.insert(serialized_string.end(),
			this->handshake.body.finished->verify_data.begin(),
			this->handshake.body.finished->verify_data.end());
		break;
	default:
		break;
	}
	/*serialized_string.push_back(this->supported_signature_hash_algorithms.size());
	for (const auto& algo : this->supported_signature_hash_algorithms) {
		serialized_string.push_back(static_cast<char>(algo.signature));
		serialized_string.push_back(static_cast<char>(algo.hash));
	}*/

	return serialized_string;
}

void TLSHandshakeProtocol::deserialize_handshake_protocol_data(std::string serialized_string, HandshakeType msg_type) {

	/* Initialization */

	// Client/Server Hello
	uint16_t session_id_length = 0;
	std::vector<CipherSuite> cipher_suites;
	uint16_t cipher_suites_length = 0;
	uint8_t compression_methods_length = 0;
	uint16_t extensions_length = 0;
	// Certificate
	uint32_t certificate_list_length = 0;
	uint32_t certificate_size = 0;
	// Certificate Request
	uint32_t certificate_types_length = 0;
	uint32_t certificate_authorities_length = 0;
	// Certificate Verify
	uint32_t handshake_messages_length = 0;
	// Client Key Exchange
	uint16_t EncryptedPreMaster_length = 0;
	// Finished
	uint32_t verify_data_length = 0;


	uint32_t random_bytes_length = 0;
	uint32_t vector_size = 0;

	auto it = serialized_string.begin();

	// Deserialize the record layer.
	this->TLS_record_layer.deserialize_record_layer_data(it, serialized_string);
	// Deserialize the HandshakeType.
	this->handshake.msg_type = static_cast<HandshakeType>(*it);
	it++;
	// Deserialize the handshake length.
	this->handshake.length = deserialize_3_bytes(it);

	// Deserialize the handshake body.
	switch (msg_type) {
	case CLIENT_HELLO:
		// ProtocolVersion
		this->handshake.body.clientHello->client_version.major = *it;
		it++;
		this->handshake.body.clientHello->client_version.minor = *it;
		it++;
		// Random.gmt_unix_time
		this->handshake.body.clientHello->random.gmt_unix_time = deserialize_4_bytes(it);
		// Random.random_bytes
		this->handshake.body.clientHello->random.random_bytes = deserialize_28_bytes(it);
		// SessionID
		session_id_length = *it;
		it++;
		if (session_id_length > 0) {
			this->handshake.body.clientHello->session_id = deserialize_32_bytes(it);
		}
		// CipherSuites
		cipher_suites_length = deserialize_2_bytes(it);
		for (int i = 0; i < cipher_suites_length; i += 2) {
			CipherSuite cipher_suite = { *it, *(it + 1) };
			cipher_suites.push_back(cipher_suite);
			it += sizeof(CipherSuite);
		}
		this->handshake.body.clientHello->cipher_suites = cipher_suites;
		// CompressionMethods
		compression_methods_length = *it;
		it++;
		for (int i = 0; i < compression_methods_length; ++i, ++it) {
			this->handshake.body.clientHello->compression_methods[i] = static_cast<CompressionMethod>(*it);
		}
		// Extensions
		extensions_length = deserialize_2_bytes(it);
		it++;
		if (extensions_length > 0) {
			this->handshake.body.clientHello->extensions_present = true;
			for (uint16_t i = 0; i < extensions_length; i += sizeof(Extension)) {
				// Read the Extension
				Extension extension(it, it + sizeof(Extension));
				this->handshake.body.clientHello->extensions_union.extensions.push_back(extension);
				it += sizeof(Extension);
			}
		}
		break;
	case SERVER_HELLO:
		// ProtocolVersion
		this->handshake.body.serverHello->server_version.major = *it;
		it++;
		this->handshake.body.serverHello->server_version.minor = *it;
		it++;
		// Random.gmt_unix_time
		this->handshake.body.serverHello->random.gmt_unix_time = deserialize_4_bytes(it);
		this->handshake.body.serverHello->random.random_bytes = deserialize_28_bytes(it);
		// SessionID
		session_id_length = *it;
		it++;
		if (session_id_length > 0) {
			this->handshake.body.serverHello->session_id = deserialize_32_bytes(it);
		}
		// CipherSuite
		for (uint16_t i = 0; i < sizeof(CipherSuite); ++i, ++it) {
			this->handshake.body.serverHello->cipher_suite[i] = static_cast<uint8_t>(*it);
		}
		// CompressionMethod
		compression_methods_length = *it;
		it++;
		this->handshake.body.serverHello->compression_method = static_cast<CompressionMethod>(*it);
		// Extensions
		//break;
		it++;
		extensions_length = *it;
		it++;
		if (extensions_length > 0) {
			this->handshake.body.serverHello->extensions_present = true;
			for (uint16_t i = 0; i < extensions_length; ) {
				// Read the Extension
				Extension extension(it, it + extensions_length);
				this->handshake.body.serverHello->extensions_union.extensions.push_back(extension);
				it += extensions_length;
				i += extensions_length;
			}
		}
		break;
	case CERTIFICATE:
		// Deserialize certificate struct
		certificate_list_length = deserialize_3_bytes(it);
		this->handshake.body.certificate->certificate_list.resize(certificate_list_length - CERTIFICATE_HANDSHAKE_OFFSET_LENGTH);
		for (size_t i = 0, cartificate_index = 0; i < certificate_list_length - CERTIFICATE_HANDSHAKE_OFFSET_LENGTH; ) {
			// Read the size of the next Certificate
			certificate_size = deserialize_3_bytes(it);

			// Read the Certificate
			std::vector<uint8_t> certificate(it, it + certificate_size);
			this->handshake.body.certificate->certificate_list[cartificate_index++] = certificate;
			it += certificate_size;
			i += certificate_size;
		}
		break;
	case SERVER_KEY_EXCHANGE:
		// Deserialize serverKeyExchange struct
		this->handshake.body.serverKeyExchange->key_exchange_algorithm = static_cast<KeyExchangeAlgorithm>(*it);
		it++;
		switch (this->handshake.body.serverKeyExchange->key_exchange_algorithm) {
		case DH_ANON:
			// DH parameters
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_p.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_p.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_p[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_g.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_g.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_g[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_Ys.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_Ys.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dh_anon.params.dh_Ys[i] = *it;
			}
			break;
		case DHE_RSA:
			// DH parameters
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_p.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_p.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_p[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_g.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_g.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_g[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_Ys.resize(vector_size);
			for (int i = 0; i < this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_Ys.size(); i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.params.dh_Ys[i] = *it;
			}

			// SignedParams.client_random.gmt_unix_time
			for (size_t i = 0; i < sizeof(uint32_t); ++i) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.client_random.gmt_unix_time
					|= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) >> (i * 8));
			}
			// SignedParams.client_random.random_bytes
			random_bytes_length = read_uint32_from_iterator(it);
			for (int i = 0; i < random_bytes_length; ++i, ++it) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes[i]
					= static_cast<uint8_t>(*it);
			}

			// SignedParams.server_random.gmt_unix_time
			for (size_t i = 0; i < sizeof(uint32_t); ++i) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.server_random.gmt_unix_time
					|= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) >> (i * 8));
			}
			// SignedParams.server_random.random_bytes
			random_bytes_length = read_uint32_from_iterator(it);
			for (int i = 0; i < random_bytes_length; ++i, ++it) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes[i]
					= static_cast<uint8_t>(*it);
			}

			// SignedParams.params
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_p.resize(vector_size);
			for (int i = 0; i < vector_size; i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_p[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_g.resize(vector_size);
			for (int i = 0; i < vector_size; i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_g[i] = *it;
			}
			vector_size = read_uint32_from_iterator(it);
			this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.resize(vector_size);
			for (int i = 0; i < vector_size; i++, it++) {
				this->handshake.body.serverKeyExchange->server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys[i] = *it;
			}
			break;
		default:
			break;
		}
		break;
	case CERTIFICATE_REQUEST:
		// Deserialize certificateRequest struct
		certificate_types_length = read_uint32_from_iterator(it);
		for (int i = 0; i < certificate_types_length; i++, it++) {
			this->handshake.body.certificateRequest->certificate_types[i] = static_cast<ClientCertificateType>(*it);
		}
		certificate_authorities_length = read_uint32_from_iterator(it);
		for (int i = 0; i < certificate_authorities_length; i++) {
			vector_size = read_uint32_from_iterator(it);
			std::vector<uint8_t> authority(it, it + vector_size);
			this->handshake.body.certificateRequest->certificate_authorities[i] = authority;
			it += vector_size;
		}
		break;
	case SERVER_HELLO_DONE:
		this->handshake.length = deserialize_3_bytes(it);
		break;
	case CERTIFICATE_VERIFY:
		// Deserialize certificateVerify struct
		handshake_messages_length = read_uint32_from_iterator(it);
		for (int i = 0; i < handshake_messages_length; i++, it++) {
			this->handshake.body.certificateVerify->digitally_signed.handshake_messages[i] = *it;
		}
		break;
	case CLIENT_KEY_EXCHANGE:
		// Deserialize clientKeyExchange struct
		switch (this->handshake.body.clientKeyExchange->key_exchange_algorithm) {
		case KEY_EXCHANGE_ALGORITHM_RSA:
			// EncryptedPreMasterSecret.client_version
			EncryptedPreMaster_length = deserialize_2_bytes(it);
			for (int i = 0; i < PRE_MASTER_SECRET_ENCRYPTED_SIZE; i++, it++) {
				this->handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret[i] = *it;
			}
			break;
		case DH_ANON:
			// PublicValueEncoding
			this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding = static_cast<PublicValueEncoding>(*it);
			it++;
			switch (this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding) {
			case EXPLICIT:
				// DHPublic.dh_Yc
				vector_size = read_uint32_from_iterator(it);
				for (int i = 0; i < vector_size; i++, it++) {
					this->handshake.body.clientKeyExchange->client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc[i] = *it;
				}
				break;
			case IMPLICIT:
				break;
			}
			break;
		}
		break;
	case FINISHED:
		// Deserialize finished struct
		verify_data_length = read_uint32_from_iterator(it);
		for (int i = 0; i < verify_data_length; i++, it++) {
			this->handshake.body.finished->verify_data[i] = *it;
		}
		break;
	default:
		break;
	}
}