#pragma once

#include "tls_definition.hpp"
#include "L5.h"

#include <iostream>
#include <array>
#include <vector>
#include <iterator>
#include <string>
#include <ctime>

#include <openssl/ssl.h>
#include <openssl/err.h>

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

		/* Constructor */
		TLSRecordLayer() {
			this->protocol_version = { 3, 3 };
			this->content_type = TLS_CONTENT_TYPE_MAX_VALUE;
			this->length = 0;
			this->fragment = { };
		}

		/* Destructor */
		~TLSRecordLayer() { }

		/* Method used for serializing the record layer data into a string type for sending. */
		std::string serialize_record_layer_data() {
			std::string serialized_string;

			/* Insert the members into the serialized_string. */
			serialized_string.push_back(this->protocol_version.major);
			serialized_string.push_back(this->protocol_version.minor);
			serialized_string.push_back(this->content_type);
			for (int i = 1; i >= 0; --i) {
				serialized_string.push_back(static_cast<char>((this->length >> (i * 8)) & 0xFF));
			}
			append_size_to_string(serialized_string, this->fragment.size());
			serialized_string.insert(serialized_string.end(),
								this->fragment.begin(),
								this->fragment.end());

			return serialized_string;
		}

		/* Method used for deserializing the record layer data from a string type (receiving). */
		void deserialize_record_layer_data(std::string::const_iterator& it, const std::string& serialized_string) {

			/* Deserialize the members from the serialized_string. */
			this->protocol_version.major = *it;
			it++;
			this->protocol_version.minor = *it;
			it++;
			this->content_type = static_cast<ContentType>(*it);
			it += sizeof(ContentType);
			this->length = (*it << 8);
			it++;
			this->length |= *it;
			it++;
			uint32_t fragment_length = *it;
			it++;
			this->fragment = { it, it + fragment_length };
			it += fragment_length;
		}

		/* Function to send a TLS record */
		void send_record(TLSSocket &socket) {
			// Send the record to the socket
		}

		/* Function to receive a TLS record */
		void receive_record(TLSSocket &socket) {
			// Receive the record from the socket
		}
	};

/************************************************************************/
/*                      Change Cipher Specs Message                     */
/************************************************************************/

	class ChangeCipherSpec {
	public:
		TLSRecordLayer record_layer;
		Type type;

		/* Constructor */
		ChangeCipherSpec() {
			this->type = CHANGE_CIPHER_SPEC_MAX_VALUE;
		}

		/* Destructor */
		~ChangeCipherSpec() {
			// Clean up
		}

	};

/************************************************************************/
/*                         TLS Alert Protocol                           */
/************************************************************************/

	class TLSAlertProtocol {
	public:
		Alert alert;

		/* Constructor */
		TLSAlertProtocol() {
			this->alert.level = ALERT_LEVEL_MAX_VALUE;
			this->alert.description = ALERT_DESCRIPTION_MAX_VALUE;
		}

		/* Destructor */
		~TLSAlertProtocol() {
			// Clean up
		}

		/* Function to send a TLS alert */
		void send_alert(TLSSocket &socket) {
			// Send the alert to the socket
		}
	};

/************************************************************************/
/*                      TLS Handshake Protocol                          */
/************************************************************************/

	class TLSHandshakeProtocol {

	public:
		TLSRecordLayer TLS_record_layer;
		Handshake handshake;
		std::vector<SignatureAndHashAlgorithm> supported_signature_hash_algorithms; /* Represents SignatureAndHashAlgorithm supported_signature_algorithms<2..2 ^ 16 - 1>. */
		
		/* Constructor */
		TLSHandshakeProtocol() {

			this->TLS_record_layer = TLSRecordLayer();
			
			this->handshake.msg_type = HELLO_REQUEST;
			this->handshake.length = 0;
			
			/* Initialize supported_signature_hash_algorithms */
			this->supported_signature_hash_algorithms = { };
		}

		/* Destructor */
		~TLSHandshakeProtocol() {
			// Clean up 
		}
		protected:
		/************************** Handshake Management *****************************/

		/* Creates a handshake message to be sent. */
		void create_handshake_message(TLSSocket &socket) {
			// Create the handshake message to be sent
		}

		/* Processes an incoming handshake message. */
		void process_handshake_message(TLSSocket &socket) {
			// Process the incoming handshake message
		}

		/* Function to send a TLS handshake message */
		void send_handshake(TLSSocket &socket) {
			// Send the handshake message to the socket
		}

		/* Function to receive a TLS handshake message */
		void receive_handshake(TLSSocket &socket) {
			// Receive the handshake message from the socket
		}

		/************************** Handshake Types *****************************/
		
		/* Receives a ServerHello message. */
		void receive_server_hello(const std::vector<uint8_t>& message) {
			// Receive the serverHello message
		}
		/* Sends a Certificate message. */
		void send_certificate(TLSSocket &socket) {
			// Send the Certificate message
		}
		/* Receives a Certificate message. */
		void receive_certificate(const std::vector<uint8_t>& message) {
			// Receive the Certificate message
		}
		/* Sends a ClientKeyExchange message. */
		void send_client_key_exchange(TLSSocket &socket) {
			// Send the ClientKeyExchange message
		}
		/* Receives a ServerKeyExchange message. */
		void receive_server_key_exchange(const std::vector<uint8_t>& message) {
			// Receive the ServerKeyExchange message
		}
		/* Sends a Finished message. */
		void send_finished(TLSSocket &socket) {
			// Send the Finished message
		}
		/* Receives a Finished message. */
		void receive_finished(const std::vector<uint8_t>& message) {
			// Receive the Finished message
		}
		
		public:
		/*************************** Utils *******************************/

		/* Validates a received certificate. */
		void validate_certificate(TLSSocket &socket) {
			// Validate the received certificate
		}

		/* Generates cryptographic keys for the session. */
		void generate_session_keys(TLSSocket &socket) {
			// Generate the cryptographic keys for the session
		}

		/* Verifies the integrity of the handshake process. */
		void verify_handshake_integrity(TLSSocket &socket) {
			// Verify the integrity of the handshake process
		}

		/* Serializes the handshake data into a string type for sending. */
		std::string serialize_handshake_protocol_data(HandshakeType msg_type) {

			/* The initialization of specific data would probably be in the main code (tls_playground) */
			this->TLS_record_layer.content_type = TLS_CONTENT_TYPE_HANDSHAKE;
			this->TLS_record_layer.length = this->handshake.length;
			KeyExchangeAlgorithm clientKeyExchangeAlgorithm = this->handshake.body.clientKeyExchange.key_exchange_algorithm;
			KeyExchangeAlgorithm serverKeyExchangeAlgorithm = this->handshake.body.serverKeyExchange.key_exchange_algorithm;
			PublicValueEncoding publicValueEncoding = this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding;

			/*********************************************************************************************/

			std::string serialized_string;

			/* Append the serialized record layer string */
			serialized_string.append(this->TLS_record_layer.serialize_record_layer_data());

			/* Serialize the handshake type and its length */
			serialized_string.push_back(this->handshake.msg_type);
			for (int i = 3; i >= 0; --i) {
				serialized_string.push_back(static_cast<char>((this->handshake.length >> (i * 8)) & 0xFF));
			}

			/* Serialize the handshake body */
			switch (msg_type) {
			case CLIENT_HELLO:
				// ProtocolVersion
				serialized_string.push_back(this->handshake.body.clientHello.client_version.major);
				serialized_string.push_back(this->handshake.body.clientHello.client_version.minor);
				// Random.gmt_unix_time
				for (size_t i = 0; i < sizeof(uint32_t); ++i) {
					serialized_string.push_back(static_cast<char>((this->handshake.body.clientHello.random.gmt_unix_time >> (i * 8)) & 0xFF));
				}
				// Random.random_bytes
				serialized_string.push_back(this->handshake.body.clientHello.random.random_bytes.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientHello.random.random_bytes.begin(),
					this->handshake.body.clientHello.random.random_bytes.end());
				// SessionID
				serialized_string.push_back(this->handshake.body.clientHello.session_id.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientHello.session_id.begin(),
					this->handshake.body.clientHello.session_id.end());
				// CipherSuites
				serialized_string.push_back(this->handshake.body.clientHello.cipher_suites.size());
				for (const auto& cipher_suite : this->handshake.body.clientHello.cipher_suites) {
					serialized_string.push_back(static_cast<char>(cipher_suite[0]));
					serialized_string.push_back(static_cast<char>(cipher_suite[1]));
				}
				// CompressionMethods
				serialized_string.push_back(this->handshake.body.clientHello.compression_methods.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientHello.compression_methods.begin(),
					this->handshake.body.clientHello.compression_methods.end());
				// Extensions
				serialized_string.push_back(this->handshake.body.clientHello.extensions_present);
				if (this->handshake.body.clientHello.extensions_present) {
					serialized_string.push_back(this->handshake.body.clientHello.extensions_union.extensions.size());
					for (const auto& extension : this->handshake.body.clientHello.extensions_union.extensions) {
						serialized_string.push_back(static_cast<char>(extension.extension_type));
						serialized_string.insert(serialized_string.end(),
							extension.extension_data.begin(),
							extension.extension_data.end());
					}
				}
				break;
			case SERVER_HELLO:
				// ProtocolVersion
				serialized_string.push_back(this->handshake.body.serverHello.server_version.major);
				serialized_string.push_back(this->handshake.body.serverHello.server_version.minor);
				// Random.gmt_unix_time
				for (size_t i = 0; i < sizeof(uint32_t); ++i) {
					serialized_string.push_back(static_cast<char>((this->handshake.body.serverHello.random.gmt_unix_time >> (i * 8)) & 0xFF));
				}
				// Random.random_bytes
				serialized_string.push_back(this->handshake.body.serverHello.random.random_bytes.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.serverHello.random.random_bytes.begin(),
					this->handshake.body.serverHello.random.random_bytes.end());
				// SessionID
				serialized_string.push_back(this->handshake.body.serverHello.session_id.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.serverHello.session_id.begin(),
					this->handshake.body.serverHello.session_id.end());
				// CipherSuites
				serialized_string.push_back(this->handshake.body.serverHello.cipher_suite[0]);
				serialized_string.push_back(this->handshake.body.serverHello.cipher_suite[1]);
				// CompressionMethods
				serialized_string.push_back(this->handshake.body.serverHello.compression_methods.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.serverHello.compression_methods.begin(),
					this->handshake.body.serverHello.compression_methods.end());
				// Extensions
				serialized_string.push_back(this->handshake.body.serverHello.extensions_present);
				if (this->handshake.body.serverHello.extensions_present) {
					serialized_string.push_back(this->handshake.body.serverHello.extensions_union.extensions.size());
					for (const auto& extension : this->handshake.body.serverHello.extensions_union.extensions) {
						serialized_string.push_back(static_cast<char>(extension.extension_type));
						serialized_string.insert(serialized_string.end(),
							extension.extension_data.begin(),
							extension.extension_data.end());
					}
				}
				break;
			case CERTIFICATE:
				// CertificateList
				append_size_to_string(serialized_string, this->handshake.body.certificate.certificate_list.size());
				for (std::size_t i = 0; i < this->handshake.body.certificate.certificate_list.size(); ++i) {
					const auto& certificate = this->handshake.body.certificate.certificate_list[i];
					for (int j = 0; j < sizeof(uint32_t); ++j) {
						serialized_string.push_back(static_cast<char>((certificate.size() >> (j * 8)) & 0xFF));
					}
					serialized_string.insert(serialized_string.end(), certificate.begin(), certificate.end());
				}
				break;
			case SERVER_KEY_EXCHANGE:
				// KeyExchangeAlgorithm
				serialized_string.push_back(this->handshake.body.serverKeyExchange.key_exchange_algorithm);
				switch (serverKeyExchangeAlgorithm) {
				case DH_ANON:
					// DH parameters
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p) {
						serialized_string.push_back(byte);
					}
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g) {
						serialized_string.push_back(byte);
					}
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys) {
						serialized_string.push_back(byte);
					}
					break;
				case DHE_RSA:
					// DH parameters
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p) {
						serialized_string.push_back(byte);
					}
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g) {
						serialized_string.push_back(byte);
					}
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys) {
						serialized_string.push_back(byte);
					}
					// SignedParams.client_random.gmt_unix_time
					for (int i = 0; i < sizeof(uint32_t); ++i) {
						serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange.server_exchange_keys
							.dhe_rsa.signed_params.client_random.gmt_unix_time >> (i * 8)) & 0xFF));
					}
					// SignedParams.client_random.random_bytes
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.end());
					// SignedParams.server_random.gmt_unix_time
					for (int i = 0; i < sizeof(uint32_t); ++i) {
						serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange.server_exchange_keys
							.dhe_rsa.signed_params.server_random.gmt_unix_time >> (i * 8)) & 0xFF));
					}
					// SignedParams.server_random.random_bytes
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.end());
					// SignedParams.params
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p) {
						serialized_string.push_back(byte);
					}
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g) {
						serialized_string.push_back(byte);
					}					
					append_size_to_string(serialized_string, this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.size());
					for (const auto& byte : this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys) {
						serialized_string.push_back(byte);
					}
				}		/********************************************************************************************/
				break;
			case CERTIFICATE_REQUEST:
				// CertificateTypes
				append_size_to_string(serialized_string, this->handshake.body.certificateRequest.certificate_types.size());
				for (const auto& type : this->handshake.body.certificateRequest.certificate_types) {
					serialized_string.push_back(type);
				}
				// CertificateAuthorities
				append_size_to_string(serialized_string, this->handshake.body.certificateRequest.certificate_authorities.size());
				for (const auto& authority : this->handshake.body.certificateRequest.certificate_authorities) {
					for (int j = 0; j < sizeof(uint32_t); ++j) {
						serialized_string.push_back(static_cast<char>((authority.size() >> (j * 8)) & 0xFF));
					}
					serialized_string.insert(serialized_string.end(), authority.begin(), authority.end());
				}
				break;
			case SERVER_HELLO_DONE:
				break;
			case CERTIFICATE_VERIFY:
				// DigitallySigned.handshake_messages
				append_size_to_string(serialized_string, this->handshake.body.certificateVerify.digitally_signed.handshake_messages.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.certificateVerify.digitally_signed.handshake_messages.begin(),
					this->handshake.body.certificateVerify.digitally_signed.handshake_messages.end());
				break;
			case CLIENT_KEY_EXCHANGE:
				// KeyExchangeAlgorithm
				serialized_string.push_back(this->handshake.body.clientKeyExchange.key_exchange_algorithm);
				switch (clientKeyExchangeAlgorithm) {
				case DH_RSA:
					// EncryptedPreMasterSecret.client_version
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major);
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor);
					// EncryptedPreMasterSecret.pre_master_secret.random
					append_size_to_string(serialized_string, this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.begin(),
						this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.end());
					break;
				case DH_ANON:
					// PublicValueEncoding
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding);
					switch (publicValueEncoding) {
					case EXPLICIT:
						// DHPublic.dh_Yc
						append_size_to_string(serialized_string, this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.size());
						serialized_string.insert(serialized_string.end(),
							this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.begin(),
							this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.end());
						break;
					case IMPLICIT:
						break;
					}
					break;
				}
				break;
			case FINISHED:
				// VerifyData
				append_size_to_string(serialized_string, this->handshake.body.finished.verify_data.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.finished.verify_data.begin(),
					this->handshake.body.finished.verify_data.end());
				break;
			default:
				break;
			}
			serialized_string.push_back(this->supported_signature_hash_algorithms.size());
			for (const auto& algo : this->supported_signature_hash_algorithms) {
				serialized_string.push_back(static_cast<char>(algo.signature));
				serialized_string.push_back(static_cast<char>(algo.hash));
			}

			return serialized_string;
		}

		/* Deserializes the handshake data from a string type. */
		void deserialize_handshake_protocol_data(std::string serialized_string, HandshakeType msg_type) {

			/* Initialization */

			uint32_t session_id_length = 0;
			uint32_t cipher_suites_length = 0;
			uint32_t compression_methods_length = 0;
			uint32_t extensions_length = 0;
			uint32_t certificate_list_length = 0;
			uint32_t certificate_size = 0;
			uint32_t certificate_types_length = 0;
			uint32_t certificate_authorities_length = 0;
			uint32_t handshake_messages_length = 0;
			uint32_t verify_data_length = 0;
			uint32_t random_bytes_length = 0;
			uint32_t vector_size = 0;

			std::vector<CipherSuite> cipher_suites;

			auto it = serialized_string.begin();

			/* Deserialize TLS_record_layer's members. */
			this->TLS_record_layer.deserialize_record_layer_data(it, serialized_string);

			/* Deserialize the handshake type and its length. */
			this->handshake.msg_type = static_cast<HandshakeType>(*it);
			it++;
			this->handshake.length = (*it++ << 24) | (*it++ << 16) | (*it++ << 8) | *it++;

			/* Deserialize the handshake body. */
			switch (msg_type) {
			case CLIENT_HELLO:
				// Deserialize clientHello struct
				this->handshake.body.clientHello.client_version.major = *it;
				it++;
				this->handshake.body.clientHello.client_version.minor = *it;
				it++;
				for (size_t i = 0; i < sizeof(uint32_t); ++i) {
					this->handshake.body.clientHello.random.gmt_unix_time |= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) << (i * 8));
				}
				random_bytes_length = *it;
				it++;
				for (int i = 0; i < random_bytes_length; ++i, ++it) {
					this->handshake.body.clientHello.random.random_bytes[i] = static_cast<uint8_t>(*it);
				}
				session_id_length = *it;
				it++;
				for (int i = 0; i < session_id_length; ++i, ++it) {
					this->handshake.body.clientHello.session_id[i] = static_cast<uint8_t>(*it);
				}
				cipher_suites_length = *it;
				it++;
				
				for (int i = 0; i < cipher_suites_length; i++) {
					CipherSuite cipher_suite = { *it, *(it + 1) };
					cipher_suites.push_back(cipher_suite);
					it += sizeof(CipherSuite);
				}
				this->handshake.body.clientHello.cipher_suites = cipher_suites;

				compression_methods_length = *it;
				it++;
				for (int i = 0; i < compression_methods_length; ++i, ++it) {
					this->handshake.body.clientHello.compression_methods[i] = static_cast<CompressionMethod>(*it);
				}
				this->handshake.body.clientHello.extensions_present = *it;
				it++;
				if (this->handshake.body.clientHello.extensions_present) {
					extensions_length = *it;
					it++;
					for (size_t i = 0; i < extensions_length; i++) {
						// Read the Extension
						Extension extension(it, it + sizeof(Extension));
						this->handshake.body.clientHello.extensions_union.extensions.push_back(extension);
						it += sizeof(Extension);
					}
				}
				break;
			case SERVER_HELLO:
				// Deserialize serverHello struct
				this->handshake.body.serverHello.server_version.major = *it;
				it++;
				this->handshake.body.serverHello.server_version.minor = *it;
				it++;
				for (size_t i = 0; i < sizeof(uint32_t); ++i) {
					this->handshake.body.serverHello.random.gmt_unix_time |= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) << (i * 8));
				}
				random_bytes_length = *it;
				it++;
				for (int i = 0; i < random_bytes_length; ++i, ++it) {
					this->handshake.body.serverHello.random.random_bytes[i] = static_cast<uint8_t>(*it);
				}
				session_id_length = *it;
				it++;
				for (int i = 0; i < session_id_length; ++i, ++it) {
					this->handshake.body.serverHello.session_id[i] = static_cast<uint8_t>(*it);
				}
				for (int i = 0; i < sizeof(CipherSuite); ++i, ++it) {
					this->handshake.body.serverHello.cipher_suite[i] = static_cast<uint8_t>(*it);
				}
				compression_methods_length = *it;
				it++;
				this->handshake.body.serverHello.compression_methods.resize(compression_methods_length);
				for (int i = 0; i < compression_methods_length; ++i, ++it) {
					this->handshake.body.serverHello.compression_methods[i] = static_cast<CompressionMethod>(*it);
				}
				this->handshake.body.serverHello.extensions_present = *it;
				it++;
				if (this->handshake.body.serverHello.extensions_present) {
					extensions_length = *it;
					it++;

					for (int i = 0; i < extensions_length; i++) {
						// Read the size of the next Extension
						size_t extension_size = sizeof(Extension);

						// Read the Extension
						Extension extension (it, it + extension_size);
						this->handshake.body.serverHello.extensions_union.extensions.push_back(extension);
						it += extension_size;
					}
				}
				break;
			case CERTIFICATE:
				// Deserialize certificate struct
				certificate_list_length = read_uint32_from_iterator(it);
				for (int i = 0; i < certificate_list_length; i++) {
					// Read the size of the next Certificate
					certificate_size = read_uint32_from_iterator(it);

					// Read the Certificate
					std::vector<uint8_t> certificate(it, it + certificate_size);
					this->handshake.body.certificate.certificate_list[i] = certificate;
					it += certificate_size;
				}
				break;
			case SERVER_KEY_EXCHANGE:
				// Deserialize serverKeyExchange struct
				this->handshake.body.serverKeyExchange.key_exchange_algorithm = static_cast<KeyExchangeAlgorithm>(*it);
				it++;
				switch(this->handshake.body.serverKeyExchange.key_exchange_algorithm) {
					case DH_ANON:
						// DH parameters
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys[i] = *it;
						}
						break;
					case DHE_RSA:
						// DH parameters
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.resize(vector_size);
						for (int i = 0; i < this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.size(); i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys[i] = *it;
						}

						// SignedParams.client_random.gmt_unix_time
						for (size_t i = 0; i < sizeof(uint32_t); ++i) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.gmt_unix_time
								|= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) >> (i * 8));
						}
						// SignedParams.client_random.random_bytes
						random_bytes_length = read_uint32_from_iterator(it);
						for (int i = 0; i < random_bytes_length; ++i, ++it) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes[i]
								= static_cast<uint8_t>(*it);
						}

						// SignedParams.server_random.gmt_unix_time
						for (size_t i = 0; i < sizeof(uint32_t); ++i) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.gmt_unix_time
								|= (static_cast<uint32_t>(static_cast<uint8_t>(*it++)) >> (i * 8));
						}
						// SignedParams.server_random.random_bytes
						random_bytes_length = read_uint32_from_iterator(it);
						for (int i = 0; i < random_bytes_length; ++i, ++it) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes[i]
								= static_cast<uint8_t>(*it);
						}

						// SignedParams.params
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.resize(vector_size);
						for (int i = 0; i < vector_size; i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.resize(vector_size);
						for (int i = 0; i < vector_size; i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g[i] = *it;
						}
						vector_size = read_uint32_from_iterator(it);
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.resize(vector_size);
						for (int i = 0; i < vector_size; i++, it++) {
							this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys[i] = *it;
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
					this->handshake.body.certificateRequest.certificate_types[i] = static_cast<ClientCertificateType>(*it);
				}
				certificate_authorities_length = read_uint32_from_iterator(it);
				for (int i = 0; i < certificate_authorities_length; i++) {
					vector_size = read_uint32_from_iterator(it);
					std::vector<uint8_t> authority(it, it + vector_size);
					this->handshake.body.certificateRequest.certificate_authorities[i] = authority;
					it += vector_size;
				}
				break;
			case SERVER_HELLO_DONE:
				break;
			case CERTIFICATE_VERIFY:
				// Deserialize certificateVerify struct
				handshake_messages_length = read_uint32_from_iterator(it);
				for (int i = 0; i < handshake_messages_length; i++, it++) {
					this->handshake.body.certificateVerify.digitally_signed.handshake_messages[i] = *it;
				}
				break;
			case CLIENT_KEY_EXCHANGE:
				// Deserialize clientKeyExchange struct
				this->handshake.body.clientKeyExchange.key_exchange_algorithm = static_cast<KeyExchangeAlgorithm>(*it);
				it++;
				switch (this->handshake.body.clientKeyExchange.key_exchange_algorithm) {
				case DH_RSA:
					// EncryptedPreMasterSecret.client_version
					this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major = *it;
					it++;
					this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor = *it;
					it++;
					// EncryptedPreMasterSecret.pre_master_secret.random
					random_bytes_length = read_uint32_from_iterator(it);
					for (int i = 0; i < random_bytes_length; i++, it++) {
						this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random[i] = *it;
					}
					break;
					case DH_ANON:
						// PublicValueEncoding
						this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding = static_cast<PublicValueEncoding>(*it);
						it++;
						switch (this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding) {
						case EXPLICIT:
							// DHPublic.dh_Yc
							vector_size = read_uint32_from_iterator(it);
							for (int i = 0; i < vector_size; i++, it++) {
								this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc[i] = *it;
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
					this->handshake.body.finished.verify_data[i] = *it;
				}
				break;

			default:
				break;
			}
		}
	};
} // namespace netlab 