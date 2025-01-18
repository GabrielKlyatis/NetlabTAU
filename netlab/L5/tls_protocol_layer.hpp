#pragma once

#include "tls_definition.hpp"

#include <iterator>
#include <ctime>

namespace netlab {

/************************************************************************/
/*                         TLS Record Layer                             */
/************************************************************************/

	class TLSRecordLayer {
	public:

		ProtocolVersion protocol_version;
		ContentType content_type;
		uint16_t length;
		std::vector<uint8_t> fragment;

		// Constructor
		TLSRecordLayer()
			: protocol_version{ 3, 3 },
			content_type(TLS_CONTENT_TYPE_HANDSHAKE),
			length(RECORD_LAYER_DEFAULT_LENGTH),
			fragment{}
		{ }

		// Serialize Record Layer Data.
		std::string serialize_record_layer_data();

		// Deserialize Record Layer Data.
		void deserialize_record_layer_data(std::string::const_iterator& it, const std::string& serialized_string);
	};
/************************************************************************/
/*                      Change Cipher Specs Message                     */
/************************************************************************/

	class ChangeCipherSpec {
	public:
		TLSRecordLayer TLS_record_layer;
		Type type;

		// Constructor
		ChangeCipherSpec() : type(CHANGE_CIPHER_SPEC_MAX_VALUE) { }

		// Set ChangeCipherSpec Members:
		void setChangeCipherSpec() {
			this->type = CHANGE_CIPHER_SPEC;
			this->TLS_record_layer.content_type = TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
			this->TLS_record_layer.length = CHANGE_CIPHER_SPEC_RECORD_LAYER_LENGTH;
		}

		// ChangeCipherSpec Serialization Method
		std::string serialize_change_cipher_spec_data();
		
		// ChangeCipherSpec Deserialization Method
		void deserialize_change_cipher_spec_data(std::string serialized_string);
	};

/************************************************************************/
/*                         TLS Alert Protocol                           */
/************************************************************************/

	class TLSAlertProtocol {
	public:
		Alert alert;
		// Constructor
		TLSAlertProtocol() : alert{ ALERT_LEVEL_MAX_VALUE, ALERT_DESCRIPTION_MAX_VALUE } { }
	};

/************************************************************************/
/*                      TLS Handshake Protocol                          */
/************************************************************************/

	class TLSHandshakeProtocol {

	public:
		TLSRecordLayer TLS_record_layer;
		Handshake handshake;
		std::vector<SignatureAndHashAlgorithm> supported_signature_hash_algorithms; /* Represents SignatureAndHashAlgorithm supported_signature_algorithms<2..2 ^ 16 - 1>. */
		
		// Constructor
		TLSHandshakeProtocol() : TLS_record_layer(), handshake{ HELLO_REQUEST, 0 }, supported_signature_hash_algorithms{} { }
		
		void updateHandshakeProtocol(HandshakeType msg_type);

		// Serialize Handshake Protocol Data.
		std::string serialize_handshake_protocol_data(HandshakeType msg_type);

		// Deserializes the handshake data from a string type.
		void deserialize_handshake_protocol_data(std::string serialized_string, HandshakeType msg_type);
	};
} // namespace netlab 