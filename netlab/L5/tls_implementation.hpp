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
		ChangeCipherSpec change_cipher_spec;
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

			/* Initialize ChangeCipherSpec */
			this->change_cipher_spec = ChangeCipherSpec();

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

		/************************** Handshake Steps *****************************/

		/* Sends a ClientHello message. */
		void send_client_hello(TLSSocket &socket) {
			
			this->TLS_record_layer.content_type = TLS_CONTENT_TYPE_HANDSHAKE;
			this->TLS_record_layer.length = this->handshake.length;

			this->handshake.msg_type = CLIENT_HELLO;
			this->handshake.body.clientHello.random.gmt_unix_time = time(0);
			this->handshake.body.clientHello.random.random_bytes = generate_random_bytes<28>();
			this->handshake.body.clientHello.session_id = generate_random_bytes<32>();
			this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA);
			this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA);
			this->handshake.body.clientHello.cipher_suites.push_back(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
			this->handshake.body.clientHello.cipher_suites.push_back(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
			this->handshake.body.clientHello.cipher_suites.push_back(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
			
			std::string serialized_client_hello;

			// Serialize the clientHello message
			serialized_client_hello.push_back(this->handshake.body.clientHello.client_version.major);
			serialized_client_hello.push_back(this->handshake.body.clientHello.client_version.minor);
			serialized_client_hello.push_back(this->handshake.body.clientHello.random.gmt_unix_time);

			serialized_client_hello.insert(serialized_client_hello.end(),
				this->handshake.body.clientHello.random.random_bytes.begin(), this->handshake.body.clientHello.random.random_bytes.end());
			serialized_client_hello.insert(serialized_client_hello.end(),
				this->handshake.body.clientHello.session_id.begin(), this->handshake.body.clientHello.session_id.end());
			serialized_client_hello.insert(serialized_client_hello.end(),
				this->handshake.body.clientHello.cipher_suites.begin(), this->handshake.body.clientHello.cipher_suites.end());
			serialized_client_hello.insert(serialized_client_hello.end(),
				this->handshake.body.clientHello.compression_methods.begin(), this->handshake.body.clientHello.compression_methods.end());

			serialized_client_hello.push_back(this->handshake.body.clientHello.extensions_present);
			if (this->handshake.body.clientHello.extensions_present) {
				serialized_client_hello.insert(serialized_client_hello.end(),
					this->handshake.body.clientHello.extensions_union.extensions.begin(), this->handshake.body.clientHello.extensions_union.extensions.end());
			}

		}
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