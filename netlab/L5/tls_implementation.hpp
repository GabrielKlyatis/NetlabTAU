#pragma once

#include "tls_definition.hpp"
#include "tls_socket.h"
#include "L5.h"

#include <iostream>
#include <array>
#include <vector>
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
		~TLSRecordLayer() {
			// Clean up

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

		TLSRecordLayer TLS_record_layer;
		Handshake handshake;
		std::vector<SignatureAndHashAlgorithm> supported_signature_hash_algorithms; /* Represents SignatureAndHashAlgorithm supported_signature_algorithms<2..2 ^ 16 - 1>. */

		/* Constructor */
		TLSHandshakeProtocol() {

			this->TLS_record_layer = TLSRecordLayer();

			this->handshake.msg_type = HANDSHAKE_TYPE_MAX_VALUE;
			this->handshake.length = 0;

			/* Initialize clientHello */
			this->handshake.body.clientHello.client_version = this->TLS_record_layer.protocol_version;
			this->handshake.body.clientHello.random.gmt_unix_time = 0;
			this->handshake.body.clientHello.random.random_bytes = { };
			this->handshake.body.clientHello.session_id = { };
			this->handshake.body.clientHello.cipher_suites = {
				TLS_NULL_WITH_NULL_NULL,
				TLS_RSA_WITH_NULL_MD5,
				TLS_RSA_WITH_NULL_SHA,
				TLS_RSA_WITH_NULL_SHA256,
				TLS_RSA_WITH_RC4_128_MD5,
				TLS_RSA_WITH_RC4_128_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
				TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
				TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_DH_DSS_WITH_AES_128_CBC_SHA,
				TLS_DH_RSA_WITH_AES_128_CBC_SHA,
				TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_DH_DSS_WITH_AES_256_CBC_SHA,
				TLS_DH_RSA_WITH_AES_256_CBC_SHA,
				TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
				TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
				TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
				TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
				TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
				TLS_DH_anon_WITH_RC4_128_MD5,
				TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
				TLS_DH_anon_WITH_AES_128_CBC_SHA,
				TLS_DH_anon_WITH_AES_256_CBC_SHA,
				TLS_DH_anon_WITH_AES_128_CBC_SHA256,
				TLS_DH_anon_WITH_AES_256_CBC_SHA256
			};
			this->handshake.body.clientHello.compression_methods = { NULL_COMPRESSION, COMPRESSION_METHOD_MAX_VALUE };
			this->handshake.body.clientHello.extensions_present = false;
			this->handshake.body.clientHello.extensions_union.no_extensions = {};

			/* Initialize serverHello */
			this->handshake.body.serverHello.server_version = this->TLS_record_layer.protocol_version;
			this->handshake.body.serverHello.random.gmt_unix_time = 0;
			this->handshake.body.serverHello.random.random_bytes = { };
			this->handshake.body.serverHello.session_id = { };
			this->handshake.body.serverHello.cipher_suite = TLS_NULL_WITH_NULL_NULL;
			this->handshake.body.serverHello.compression_methods = { NULL_COMPRESSION, COMPRESSION_METHOD_MAX_VALUE };
			this->handshake.body.serverHello.extensions_present = false;
			this->handshake.body.serverHello.extensions_union.no_extensions = {};

			/* Initialize Certificate */
			this->handshake.body.certificate.certificate_list = { };

			/* Initialize ServerKeyExchange */
			this->handshake.body.serverKeyExchange.key_exchange_algorithm = KEY_EXCHANGE_ALGORITHM_MAX_VALUE;
			this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p = { };
			this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys = { };

			/* Initialize CertificateRequest */
			this->handshake.body.certificateRequest.certificate_types = { };
			this->handshake.body.certificateRequest.certificate_authorities = { };

			/* Initialize certificateVerify */
			this->handshake.body.certificateVerify.digitally_signed.handshake_messages = { };
			
			/* Initialize ClientKeyExchange */
			this->handshake.body.clientKeyExchange.key_exchange_algorithm = KEY_EXCHANGE_ALGORITHM_MAX_VALUE;
			this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version = this->TLS_record_layer.protocol_version;
			this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = { };
			this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding = IMPLICIT;
			this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.implicit = { };

			/* Initialize Finished */
			this->handshake.body.finished.verify_data = { };

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
			/*********************************************************************************************/

			std::string serialized_string;

			/* Insert TLS_record_layer's members into the serialized_string. */
			serialized_string.push_back(this->TLS_record_layer.protocol_version.major); 
			serialized_string.push_back(this->TLS_record_layer.protocol_version.minor);
			serialized_string.push_back(this->TLS_record_layer.content_type);
			for (int i = 1; i >= 0; --i) {
				serialized_string.push_back(static_cast<char>((this->TLS_record_layer.length >> (i * 8)) & 0xFF));
			}
			serialized_string.push_back(this->TLS_record_layer.fragment.size());
			serialized_string.insert(serialized_string.end(), 
				this->TLS_record_layer.fragment.begin(), 
				this->TLS_record_layer.fragment.end());

			/* Serialize the handshake type and its length */
			serialized_string.push_back(this->handshake.msg_type);
			for (int i = 3; i >= 0; --i) {
				serialized_string.push_back(static_cast<char>((this->handshake.length >> (i * 8)) & 0xFF));
			}

			/* Serialize the handshake body */
			switch (msg_type) {
			case CLIENT_HELLO:

				/* The initialization of specific data would probably be in the main code (tls_playground) */
				this->handshake.msg_type = CLIENT_HELLO;
				this->handshake.body.clientHello.random.gmt_unix_time = time(0);
				this->handshake.body.clientHello.random.random_bytes = generate_random_bytes<28>();
				this->handshake.body.clientHello.session_id = generate_random_bytes<32>();
				this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA);
				this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA);
				this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
				this->handshake.body.clientHello.cipher_suites.push_back(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
				this->handshake.body.clientHello.cipher_suites.push_back(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
				/*********************************************************************************************/

				// ProtocolVersion
				serialized_string.push_back(this->handshake.body.clientHello.client_version.major);
				serialized_string.push_back(this->handshake.body.clientHello.client_version.minor);
				// Random.gmt_unix_time
				for (int i = 3; i >= 0; --i) {
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
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientHello.cipher_suites.begin(),
					this->handshake.body.clientHello.cipher_suites.end());
				// CompressionMethods
				serialized_string.push_back(this->handshake.body.clientHello.compression_methods.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.clientHello.compression_methods.begin(),
					this->handshake.body.clientHello.compression_methods.end());
				// Extensions
				serialized_string.push_back(this->handshake.body.clientHello.extensions_present);
				if (this->handshake.body.clientHello.extensions_present) {
					serialized_string.push_back(this->handshake.body.clientHello.extensions_union.extensions.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.clientHello.extensions_union.extensions.begin(),
						this->handshake.body.clientHello.extensions_union.extensions.end());
				}
				break;
			case SERVER_HELLO:
				// ProtocolVersion
				serialized_string.push_back(this->handshake.body.serverHello.server_version.major);
				serialized_string.push_back(this->handshake.body.serverHello.server_version.minor);
				// Random.gmt_unix_time
				for (int i = 3; i >= 0; --i) {
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
				// CipherSuite
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.serverHello.cipher_suite.begin(),
					this->handshake.body.serverHello.cipher_suite.end());
				// CompressionMethod
				serialized_string.push_back(this->handshake.body.serverHello.compression_methods.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.serverHello.compression_methods.begin(),
					this->handshake.body.serverHello.compression_methods.end());
				// Extensions
				serialized_string.push_back(this->handshake.body.serverHello.extensions_present);
				if (this->handshake.body.serverHello.extensions_present) {
					serialized_string.push_back(this->handshake.body.serverHello.extensions_union.extensions.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverHello.extensions_union.extensions.begin(),
						this->handshake.body.serverHello.extensions_union.extensions.end());
				}
				break;
			case CERTIFICATE:
				// CertificateList
				serialized_string.push_back(this->handshake.body.certificate.certificate_list.size());
				for (const auto& certificate : this->handshake.body.certificate.certificate_list) {
					uint16_t certificate_size = static_cast<uint16_t>(certificate.size());
					serialized_string.push_back((certificate_size >> 8) & 0xFF);  // High byte
					serialized_string.push_back(certificate_size & 0xFF);  // Low byte
					serialized_string.insert(serialized_string.end(), certificate.begin(), certificate.end());
				}
				break;
			case SERVER_KEY_EXCHANGE:
				// KeyExchangeAlgorithm
				serialized_string.push_back(this->handshake.body.serverKeyExchange.key_exchange_algorithm);
				KeyExchangeAlgorithm keyExchangeAlgorithm = this->handshake.body.serverKeyExchange.key_exchange_algorithm;
				switch (keyExchangeAlgorithm) {
				case DH_ANON:
					// DH parameters
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_g.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_p.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dh_anon.params.dh_Ys.end());
					break;
				case DHE_RSA:
					// DH parameters
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_g.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_p.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.params.dh_Ys.end());
					// SignedParams.client_random.gmt_unix_time
					for (int i = 3; i >= 0; --i) {
						serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.gmt_unix_time >> (i * 8)) & 0xFF));
					}
					// SignedParams.client_random.random_bytes
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.client_random.random_bytes.end());
					// SignedParams.server_random.gmt_unix_time
					for (int i = 3; i >= 0; --i) {
						serialized_string.push_back(static_cast<char>((this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.gmt_unix_time >> (i * 8)) & 0xFF));
					}
					// SignedParams.server_random.random_bytes
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.server_random.random_bytes.end());

					/* Need to check why is this needed inside signed_params. */
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_g.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_p.end());
					serialized_string.push_back(this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.begin(),
						this->handshake.body.serverKeyExchange.server_exchange_keys.dhe_rsa.signed_params.params.dh_Ys.end());
				}		/********************************************************************************************/

				break;
			case CERTIFICATE_REQUEST:
				// CertificateTypes
				serialized_string.push_back(this->handshake.body.certificateRequest.certificate_types.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.certificateRequest.certificate_types.begin(),
					this->handshake.body.certificateRequest.certificate_types.end());
				// CertificateAuthorities
				serialized_string.push_back(this->handshake.body.certificateRequest.certificate_authorities.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.certificateRequest.certificate_authorities.begin(),
					this->handshake.body.certificateRequest.certificate_authorities.end());
				break;
			case SERVER_HELLO_DONE:
				break;
			case CERTIFICATE_VERIFY:
				// DigitallySigned.handshake_messages
				serialized_string.push_back(this->handshake.body.certificateVerify.digitally_signed.handshake_messages.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.certificateVerify.digitally_signed.handshake_messages.begin(),
					this->handshake.body.certificateVerify.digitally_signed.handshake_messages.end());
				break;
			case CLIENT_KEY_EXCHANGE:
				// KeyExchangeAlgorithm
				serialized_string.push_back(this->handshake.body.clientKeyExchange.key_exchange_algorithm);
				KeyExchangeAlgorithm keyExchangeAlgorithm = this->handshake.body.clientKeyExchange.key_exchange_algorithm;
				switch (keyExchangeAlgorithm) {
				case KEY_EXCHANGE_ALGORITHM_RSA:
					// EncryptedPreMasterSecret.client_version
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major);
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor);
					// EncryptedPreMasterSecret.pre_master_secret.random
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.size());
					serialized_string.insert(serialized_string.end(),
						this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.begin(),
						this->handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random.end());
					break;
				case DH_ANON:
					// PublicValueEncoding
					serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding);
					PublicValueEncoding publicValueEncoding = this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding;
					switch (publicValueEncoding) {
					case EXPLICIT:
						// DHPublic.dh_Yc
						serialized_string.push_back(this->handshake.body.clientKeyExchange.client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.size());
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
				serialized_string.push_back(this->handshake.body.finished.verify_data.size());
				serialized_string.insert(serialized_string.end(),
					this->handshake.body.finished.verify_data.begin(),
					this->handshake.body.finished.verify_data.end());
				break;
			default:
				break;
			}
			serialized_string.push_back(this->supported_signature_hash_algorithms.size());
			serialized_string.insert(serialized_string.end(),
				this->supported_signature_hash_algorithms.begin(), 
				this->supported_signature_hash_algorithms.end());

			return serialized_string;
		}

		/* Deserializes the handshake data from a string type. */
		TLSHandshakeProtocol& deserialize_handshake_protocol_data(std::string serialized_string, HandshakeType msg_type) {

			TLSHandshakeProtocol protocol;
			auto it = serialized_string.begin();

			/* Deserialize TLS_record_layer's members. */
			protocol.TLS_record_layer.protocol_version.major = *it;
			it++;
			protocol.TLS_record_layer.protocol_version.minor = *it;
			it++;
			protocol.TLS_record_layer.content_type = static_cast<ContentType>(*it);
			it += sizeof(ContentType);
			protocol.TLS_record_layer.length = (*it << 8);
			it++;
			protocol.TLS_record_layer.length |= *it;
			it++;
			auto fragment_length = *it;
			it++;
			protocol.TLS_record_layer.fragment = { it, it + fragment_length };
			it += fragment_length;


			/* Deserialize the handshake type and its length. */
			protocol.handshake.msg_type = static_cast<HandshakeType>(*it);
			it++;
			protocol.handshake.length = (*it++ << 24) | (*it++ << 16) | (*it++ << 8) | *it++;

			/* Deserialize the handshake body. */
			switch (msg_type) {
			case CLIENT_HELLO:
				protocol.handshake.body.clientHello.client_version.major = *it;
				it++;
				protocol.handshake.body.clientHello.client_version.minor = *it;
				it++;
				protocol.handshake.body.clientHello.random.gmt_unix_time = (*it++ << 24) | (*it++ << 16) | (*it++ << 8) | *it++;
				auto random_bytes_length = *it;
				it++;
				std::copy_n(it, random_bytes_length, protocol.handshake.body.clientHello.random.random_bytes.begin());
				it += random_bytes_length;
				auto session_id_length = *it;
				it++;
				std::copy_n(it, session_id_length, protocol.handshake.body.clientHello.session_id.begin());
				it += session_id_length;
				auto cipher_suites_length = *it;
				it++;
				for (int i = 0; i < cipher_suites_length; i++) {
					std::copy_n(it, sizeof(CipherSuite), protocol.handshake.body.clientHello.cipher_suites.begin()); //TODO
					it += sizeof(CipherSuite);
				}
				auto compression_methods_length = *it;
				it++;
				std::copy_n(it, compression_methods_length, protocol.handshake.body.clientHello.compression_methods.begin());
				it += compression_methods_length;
				protocol.handshake.body.clientHello.extensions_present = *it;
				it++;
				if (protocol.handshake.body.clientHello.extensions_present) {
					auto extensions_length = *it;
					it++;
					for (int i = 0; i < extensions_length; i++) {
						std::copy_n(it, sizeof(Extension), protocol.handshake.body.clientHello.extensions_union.extensions.begin()); //TODO
						it += sizeof(Extension);
					}
				}
				break;
			case SERVER_HELLO:
				protocol.handshake.body.serverHello.server_version.major = *it;
				it++;
				protocol.handshake.body.serverHello.server_version.minor = *it;
				it++;
				protocol.handshake.body.serverHello.random.gmt_unix_time = (*it++ << 24) | (*it++ << 16) | (*it++ << 8) | *it++;
				auto random_bytes_length = *it;
				it++;
				std::copy_n(it, random_bytes_length, protocol.handshake.body.serverHello.random.random_bytes.begin());
				it += random_bytes_length;
				auto session_id_length = *it;
				it++;
				std::copy_n(it, session_id_length, protocol.handshake.body.serverHello.session_id.begin());
				it += session_id_length;
				std::copy_n(it, sizeof(CipherSuite), protocol.handshake.body.serverHello.cipher_suite.begin());
				it += sizeof(CipherSuite);
				auto compression_methods_length = *it;
				it++;
				std::copy_n(it, compression_methods_length, protocol.handshake.body.serverHello.compression_methods.begin());
				it += compression_methods_length;
				protocol.handshake.body.serverHello.extensions_present = *it;
				it++;
				if (protocol.handshake.body.serverHello.extensions_present) {
					auto extensions_length = *it;
					it++;
					for (int i = 0; i < extensions_length; i++) {
						std::copy_n(it, sizeof(Extension), protocol.handshake.body.serverHello.extensions_union.extensions.begin()); //TODO
						it += sizeof(Extension);
					}
				}
				break;
			case CERTIFICATE:
				auto certificate_list_length = *it;
				it++;
				for (int i = 0; i < certificate_list_length; i++) {
					// Read the size of the next Certificate
					size_t certificate_size = *reinterpret_cast<const size_t*>(&*it);
					it += sizeof(size_t);

					// Read the Certificate
					std::vector<uint8_t> certificate(it, it + certificate_size);
					protocol.handshake.body.certificate.certificate_list.push_back(certificate);
					it += certificate_size;
				}
				break;
			case SERVER_KEY_EXCHANGE:

			default:
				break;
			}

			return protocol;
		}

		/* Generates a random byte array. */
		template <std::size_t N>
		std::array<uint8_t, N> generate_random_bytes() {
			std::array<uint8_t, N> random_bytes;
			for (std::size_t i = 0; i < N; i++) {
				random_bytes[i] = rand() % 256;
			}
			return random_bytes;
		}
	};
}