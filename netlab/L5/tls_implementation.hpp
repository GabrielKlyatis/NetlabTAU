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
			// Initialize your member variables here
		}

		/* Destructor */
		~TLSRecordLayer() {
			// Clean up your member variables here
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

	class ChangeCipherSpec : TLSHandshakeProtocol {
		Type type;

		/* Constructor */
		ChangeCipherSpec() {
			// Initialize your member variables here
		}

		/* Destructor */
		~ChangeCipherSpec() {
			// Clean up your member variables here
		}

	};

/************************************************************************/
/*                         TLS Alert Protocol                           */
/************************************************************************/

	class TLSAlertProtocol : TLSRecordLayer {
		Alert alert;

		/* Constructor */
		TLSAlertProtocol() {
			// Initialize your member variables here
		}

		/* Destructor */
		~TLSAlertProtocol() {
			// Clean up your member variables here
		}

		/* Function to send a TLS alert */
		void send_alert(TLSSocket &socket) {
			// Send the alert to the socket
		}
	};

/************************************************************************/
/*                      TLS Handshake Protocol                          */
/************************************************************************/

	class TLSHandshakeProtocol : TLSRecordLayer {

		TLSRecordLayer TLS_record_layer;
		Handshake handshake;

		std::vector<SignatureAndHashAlgorithm> supported_signature_algorithms; /* Represents SignatureAndHashAlgorithm supported_signature_algorithms<2..2 ^ 16 - 1>. */

		/* Constructor */
		TLSHandshakeProtocol() {
			// Initialize your member variables here
		}

		/* Destructor */
		~TLSHandshakeProtocol() {
			// Clean up your member variables here
		}

		/* Function to send a TLS handshake message */
		void send_handshake(TLSSocket &socket) {
			// Send the handshake message to the socket
		}

		/* Function to receive a TLS handshake message */
		void receive_handshake(TLSSocket &socket) {
			// Receive the handshake message from the socket
		}
	};
}