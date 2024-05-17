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

		TLSRecordLayer();
		~TLSRecordLayer();
		void send(const std::vector<uint8_t>& data);
		std::vector<uint8_t> receive();
		void set_socket(int socket);
		void set_tls_version(uint16_t version);
		void set_tls_version(uint8_t major, uint8_t minor);
		void set_tls_version(ProtocolVersion version);
		void set_content_type(ContentType type);
		void set_content_type(uint8_t type);
		void set_protocol_version(uint8_t major, uint8_t minor);
		void set_protocol_version(ProtocolVersion version);
		void set_protocol_version(uint16_t version);
		void set_length(uint16_t length);
		void set_fragment(const std::vector<uint8_t>& fragment);
		void set_fragment(uint8_t* fragment, size_t length);
		void set_fragment(const uint8_t* fragment, size_t length);
		void set_fragment(const char* fragment, size_t length);
		void set_fragment(const std::string& fragment);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t length);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size, size_t offset2);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size, size_t offset2, size_t length2);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size, size_t offset2, size_t length2, size_t size2);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size, size_t offset2, size_t length2, size_t size2, size_t offset3);
		void set_fragment(const std::vector<uint8_t>& fragment, size_t offset, size_t length, size_t size, size_t offset2, size_t length2, size_t size2, size_t offset3, size_t length3);
	};

/************************************************************************/
/*                      Change Cipher Specs Message                     */
/************************************************************************/

	struct ChangeCipherSpec {
		Type type;
	};

/************************************************************************/
/*                         TLS Alert Protocol                           */
/************************************************************************/

	class TLSAlertProtocol : TLSRecordLayer {
		struct Alert {

			AlertLevel level;
			AlertDescription description;
		};
	};

/************************************************************************/
/*                      TLS Handshake Protocol                          */
/************************************************************************/

	class TLSHandshakeProtocol {

		TLSRecordLayer TLS_record_layer;
		Handshake handshake;

		std::vector<SignatureAndHashAlgorithm> supported_signature_algorithms; /* Represents SignatureAndHashAlgorithm supported_signature_algorithms<2..2 ^ 16 - 1>. */
	};
}