#pragma once

#include "tls_definition.hpp"
#include "tls_socket.h"
#include "L5.h"

#include <iostream>
#include <array>
#include <vector>
#include <string>
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
			this->handshake.body.clientHello.random = { };
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
			this->handshake.body.serverHello.random = { };
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
	};
}