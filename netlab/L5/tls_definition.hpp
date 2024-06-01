#pragma once

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
/*                               #define                                */
/************************************************************************/

#define TLS_VERSION_SSLv3 = 0x0300
#define TLS_VERSION_TLSv1_0 = 0x0301
#define TLS_VERSION_TLSv1_1 = 0x0302
#define TLS_VERSION_TLSv1_2 = 0x0303
#define TLS_VERSION_TLSv1_3 = 0x0304

/************************************************************************/
/*                               typedef                                */
/************************************************************************/

	typedef std::array<uint8_t, 32> SessionID; /* Represents SessionID session_id<0..32>; */
	typedef std::array<uint8_t, 2> CipherSuite; /* Represents CipherSuite cipher_suites<2..2^16-1>; */
	typedef std::vector<uint8_t> DistinguishedName; /* Represents DistinguishedName<1..2^16-1>; */

/************************************************************************/
/*                         The Cipher Suite                             */
/************************************************************************/

	/* The following CipherSuite definitions require that the server provide
		an RSA certificate that can be used for key exchange.  The server may
		request any signature-capable certificate in the certificate request
		message.*/

	CipherSuite TLS_NULL_WITH_NULL_NULL = { 0x00,0x00 };
	CipherSuite TLS_RSA_WITH_NULL_MD5 = { 0x00,0x01 };
	CipherSuite TLS_RSA_WITH_NULL_SHA = { 0x00,0x02 };
	CipherSuite TLS_RSA_WITH_NULL_SHA256 = { 0x00,0x3B };
	CipherSuite TLS_RSA_WITH_RC4_128_MD5 = { 0x00,0x04 };
	CipherSuite TLS_RSA_WITH_RC4_128_SHA = { 0x00,0x05 };
	CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x0A };
	CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x2F };
	CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x35 };
	CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3C };
	CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x3D };

	/* The following cipher suite definitions are used for server-
	   authenticated (and optionally client-authenticated) Diffie-Hellman. */

	CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00,0x0D };
	CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x10 };
	CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00,0x13 };
	CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x16 };
	CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA = { 0x00,0x30 };
	CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x31 };
	CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA = { 0x00,0x32 };
	CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x33 };
	CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA = { 0x00,0x36 };
	CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x37 };
	CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA = { 0x00,0x38 };
	CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x39 };
	CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,0x3E };
	CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3F };
	CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,0x40 };
	CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x67 };
	CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,0x68 };
	CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x69 };
	CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,0x6A };
	CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x6B };

	/* The following cipher suites are used for completely anonymous
	   Diffie-Hellman communications in which neither party is
	   authenticated. */

	CipherSuite TLS_DH_anon_WITH_RC4_128_MD5 = { 0x00,0x18 };
	CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = { 0x00,0x1B };
	CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA = { 0x00,0x34 };
	CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA = { 0x00,0x3A };
	CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256 = { 0x00,0x6C };
	CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256 = { 0x00,0x6D };

/************************************************************************/
/*								  enums                                 */
/************************************************************************/

/**************************** TLS Record Layer **************************/

	enum ContentType {

		TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14,
		TLS_CONTENT_TYPE_ALERT = 0x15,
		TLS_CONTENT_TYPE_HANDSHAKE = 0x16,
		TLS_CONTENT_TYPE_APPLICATION_DATA = 0x17,
		TLS_CONTENT_TYPE_MAX_VALUE = 255,
	};


/************************** Change Cipher Spect ************************/

	enum Type {
		CHANGE_CIPHER_SPEC = 1,
		CHANGE_CIPHER_SPEC_MAX_VALUE = 255,
	};

/**************************** TLS Alert Protocol **************************/

	enum AlertLevel : uint8_t {

		WARNING = 1,
		FATAL = 2,
		ALERT_LEVEL_MAX_VALUE = 255,
	};

	enum AlertDescription : uint8_t {

		CLOSE_NOTIFY = 0,
		UNEXPECTED_MESSAGE = 10,
		BAD_RECORD_MAC = 20,
		DECRYPTION_FAILED_RESERVED = 21,
		RECORD_OVERFLOW = 22,
		DECOMPRESSION_FAILURE = 30,
		HANDSHAKE_FAILURE = 40,
		NO_CERTIFICATE_RESERVED = 41,
		BAD_CERTIFICATE = 42,
		UNSUPPORTED_CERTIFICATE = 43,
		CERTIFICATE_REVOKED = 44,
		CERTIFICATE_EXPIRED = 45,
		CERTIFICATE_UNKNOWN = 46,
		ILLEGAL_PARAMETER = 47,
		UNKNOWN_CA = 48,
		ACCESS_DENIED = 49,
		DECODE_ERROR = 50,
		DECRYPT_ERROR = 51,
		EXPORT_RESTRICTION_RESERVED = 60,
		PROTOCOL_VERSION = 70,
		INSUFFICIENT_SECURITY = 71,
		INTERNAL_ERROR = 80,
		USER_CANCELED = 90,
		NO_RENEGOTIATION = 100,
		UNSUPPORTED_EXTENSION = 110,
		CERTIFICATE_UNOBTAINABLE = 111,
		BAD_CERTIFICATE_STATUS_RESPONSE = 112,
		BAD_CERTIFICATE_HASH_VALUE = 113,
		UNKNOWN_PSK_IDENTITY = 115,
		NO_APPLICATION_PROTOCOL = 120,
		ALERT_DESCRIPTION_MAX_VALUE = 255,
	};

/************************ TLS Handshake Protocol ***********************/

	enum HandshakeType : uint8_t {

		HELLO_REQUEST = 0x00,
		CLIENT_HELLO = 0x01,
		SERVER_HELLO = 0x02,
		CERTIFICATE = 0x0B,
		SERVER_KEY_EXCHANGE = 0x0C,
		CERTIFICATE_REQUEST = 0x0D,
		SERVER_HELLO_DONE = 0x0E,
		CERTIFICATE_VERIFY = 0x0F,
		CLIENT_KEY_EXCHANGE = 0x10,
		FINISHED = 0x14,
		HANDSHAKE_TYPE_MAX_VALUE = 255,
	};

	enum ExtensionType {
		SIGNATURE_ALGORITHMS = 13,
		EXTENSION_TYPE_MAX_VALUE = 65535,
	};

	enum HashAlgorithm {
		HASH_ALGORITHM_NONE = 0,
		MD5 = 1,
		SHA1 = 2,
		SHA224 = 3,
		SHA256 = 4,
		SHA384 = 5,
		SHA512 = 6,
		HASH_ALGORITHM_MAX_VALUE = 255,
	};

	enum SignatureAlgorithm {
		ANONYMOUS = 0,
		SIGNATURE_ALGORITHM_RSA = 1,
		DSA = 2,
		ECDSA = 3,
		SIGNATURE_ALGORITHM_MAX_VALUE = 255,
	};

	enum KeyExchangeAlgorithm {
		KEY_EXCHANGE_ALGORITHM_RSA = 1,
		DH_DSS = 2,
		DH_RSA = 3,
		DHE_DSS = 4,
		DHE_RSA = 5,
		DH_ANON = 6,
		ECDH_ECDSA = 7,
		ECDHE_ECDSA = 8,
		ECDH_RSA = 9,
		ECDHE_RSA = 10,
		PSK = 11,
		DHE_PSK = 12,
		RSA_PSK = 13,
		ECDHE_PSK = 14,
		KEY_EXCHANGE_ALGORITHM_MAX_VALUE = 255,
	};

	enum ClientCertificateType : uint8_t {
		RSA_SIGN = 1,
		DSS_SIGN = 2,
		FIXED_DH = 3,
		DSS_FIXED_DH = 4,
		RSA_EPHEMERAL_DH_RESERVED = 5,
		DSS_EPHEMERAL_DH_RESERVED = 6,
		FORTEZZA_DMS_RESERVED = 20,
		CLIENT_CERTIFICATE_TYPE_MAX_VALUE = 255,
	};

	enum PublicValueEncoding {
		IMPLICIT,
		EXPLICIT
	};

/************************** Security Parameters *************************/

	enum CompressionMethod : uint8_t{

		NULL_COMPRESSION = 0,
		COMPRESSION_METHOD_MAX_VALUE = 255
	};

	enum ConnectionEnd {

		CLIENT,
		SERVER
	};

	enum PRFAlgorithm {

		TLS_PRF_SHA256
	};

	enum BulkCipherAlgorithm {

		NULL_CIPHER,
		RC4,
		DES3,
		AES,
	};

	enum CipherType {

		STREAM,
		BLOCK,
		AEAD
	};

	enum MACAlgorithm {

		NULL_MAC,
		HMAC_MD5,
		HMAC_SHA1,
		HMAC_SHA256,
		HMAC_SHA384,
		HMAC_SHA512
	};

/************************************************************************/
/*							     structs                                */
/************************************************************************/

/**************************** TLS Record Layer **************************/

	struct ProtocolVersion { /* TLS v1.2 uses {3,3} */
		uint8_t major;
		uint8_t minor;
	};

	struct TLSPlaintext {

		ContentType type; /* The higher-level protocol used to process the enclosed fragment. */
		ProtocolVersion version; /* TLS v1.2 uses version 0x0303. */
		uint16_t length; /* The length (in bytes) of the following TLSPlaintext.fragment. The length MUST NOT exceed 2 ^ 14. */
		std::vector<uint8_t> fragment; /* The application data - fragment[TLSPlaintext.length]. */
	};

	struct TLSCompressed {

		ContentType type; /* same as TLSPlaintext.type */
		ProtocolVersion version; /* same as TLSPlaintext.version */
		uint16_t length; /* The length(in bytes) of the following TLSCompressed.fragment.The length MUST NOT exceed 2 ^ 14 + 1024. */
		std::vector<uint8_t> fragment; /* The compressed form of TLSPlaintext.fragment - fragment[TLSCompressed.length]. */
	};

	struct GenericStreamCipher {

		std::vector<uint8_t> content; /* The encrypted data, with the MAC. (content[TLSCompressed.length]). */
		std::vector<uint8_t> MAC; /* The MAC. The length of the MAC depends on the cipher suite. (MAC[SecurityParameters.mac_length]). */
	};

	struct GenericBlockCipher {

		std::vector<uint8_t> IV; /* The initialization vector (IV) (IV[SecurityParameters.record_iv_length]). */
		struct {
			std::vector<uint8_t> content; /* The encrypted data. (content[TLSCompressed.length]). */
			std::vector<uint8_t> MAC; /* The MAC. The length of the MAC depends on the cipher suite. (MAC[SecurityParameters.mac_length]). */
			std::vector<uint8_t> padding; /* The padding.The length of the padding depends on the block length. (padding[SecurityParameters.padding_length]). */
			uint8_t padding_length; /* The padding length. The padding length MUST be such that the size of the GenericBlockCipher struct is a multiple of the block length. */
		} block_ciphered;
	};

	struct GenericAEADCipher {

		std::vector<uint8_t> nonce_explicit; /* The explicit part of the nonce. (nonce_explicit[SecurityParameters.record_iv_length]). */
		struct {
			std::vector<uint8_t> content; /* The encrypted data. (content[TLSCompressed.length]). */
		} aead_ciphered;
	};

	struct TLSCiphertext {

		ContentType type; /* The type field is identical to TLSCompressed.type. */
		ProtocolVersion version; /* The version field is identical to TLSCompressed.version. */
		uint16_t length; /* The length (in bytes) of the following TLSCiphertext.fragment. The length MUST NOT exceed 2 ^ 14 + 2048. */
		CipherType cipher_type; /* The cipher type. */

		union Fragment { /* The encrypted form of TLSCompressed.fragment, with the MAC. */
			GenericStreamCipher streamCipher;
			GenericBlockCipher blockCipher;
			GenericAEADCipher aeadCipher;
		} fragment;
	};

/************************ TLS Alert Protocol ***********************/

	struct Alert {

		AlertLevel level;
		AlertDescription description;
	};

/************************ TLS Handshake Protocol ***********************/

	struct Random {

		uint32_t gmt_unix_time; /* Timestamp in seconds since 1st January 1970. */
		std::array<uint8_t, 28> random_bytes;

		Random() : gmt_unix_time(0), random_bytes() { }
		~Random() { }
	};

	struct Extension {
		ExtensionType extension_type;;
		std::vector<uint8_t> extension_data;

		Extension(std::string::const_iterator start, std::string::const_iterator end) {
			extension_data.assign(start, end);
		}
	};

	struct HelloRequest { };

	union ExtensionUnion{
		struct { } no_extensions; /* empty */
		std::vector<Extension> extensions; /* Represents Extension extensions<0..2^16-1>; */

		ExtensionUnion() : no_extensions() {}
		~ExtensionUnion() { extensions.clear(); }
	};

	struct ClientHello {
		ProtocolVersion client_version;
		Random random;
		SessionID session_id;
		std::vector<CipherSuite> cipher_suites;
		std::vector<CompressionMethod> compression_methods;
		bool extensions_present;
		ExtensionUnion extensions_union;

		ClientHello() {
			/* Initialize clientHello */
			client_version.major = 3;
			client_version.minor = 3;
			random.gmt_unix_time = 0;
			random.random_bytes = { };
			session_id = { };
			cipher_suites.resize(1);
			cipher_suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA);
			compression_methods = { NULL_COMPRESSION, COMPRESSION_METHOD_MAX_VALUE };
			extensions_present = false;
			extensions_union.no_extensions = {};
		}
		~ClientHello() { }

		void setClientHello(uint32_t gmt_unix_time, std::array<uint8_t, 28> random_bytes, std::array<uint8_t, 32> session_id) {
			random.gmt_unix_time = gmt_unix_time;
			random.random_bytes = random_bytes;
			session_id = session_id;
		}
	};

	struct ServerHello {
		ProtocolVersion server_version;
		Random random;
		SessionID session_id;
		CipherSuite cipher_suite;
		std::vector<CompressionMethod> compression_methods;
		bool extensions_present;
		ExtensionUnion extensions_union;

		ServerHello() {
			/* Initialize serverHello */
			server_version.major = 3;
			server_version.minor = 3;
			random.gmt_unix_time = 0;
			random.random_bytes = { };
			session_id = { };
			cipher_suite = TLS_NULL_WITH_NULL_NULL;
			compression_methods = { NULL_COMPRESSION, COMPRESSION_METHOD_MAX_VALUE };
			extensions_present = false;
			extensions_union.no_extensions = {};
		}
		~ServerHello() { }

		void setServerHello(uint32_t gmt_unix_time, std::array<uint8_t, 28> random_bytes, std::array<uint8_t, 32> session_id) {
			random.gmt_unix_time = gmt_unix_time;
			random.random_bytes = random_bytes;
			session_id = session_id;
			cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA;
		}
	};

	struct SignatureAndHashAlgorithm {
		HashAlgorithm hash;
		SignatureAlgorithm signature;
	};

	struct Certificate {
		std::vector<std::vector<uint8_t>> certificate_list; /* Represents ASN.1Cert certificate_list<0..2 ^ 24 - 1>. */

		Certificate() : certificate_list() { }
		~Certificate() { }
	};

	struct ServerDHParams {
		std::vector<uint8_t> dh_p;
		std::vector<uint8_t> dh_g;
		std::vector<uint8_t> dh_Ys;

		ServerDHParams() : dh_p(), dh_g(), dh_Ys() { }
		~ServerDHParams() { }
	};

	struct ServerKeyExchange {
		KeyExchangeAlgorithm key_exchange_algorithm;
		union ServerExchangeKeys{
			struct dhANON {
				ServerDHParams params;

				dhANON() : params() { }
				~dhANON() { }

			} dh_anon; /* KeyExchangeAlgorithm = DH_ANON (6)*/

			struct dheRSA{ /* KeyExchangeAlgorithm = DHE_RSA (5) */
				ServerDHParams params;
				struct SignedParams{
					Random client_random;
					Random server_random;
					ServerDHParams params;

					SignedParams() : client_random(), server_random(), params() { }
					~SignedParams() { }

				} signed_params;

				dheRSA() : params(), signed_params() { }
				~dheRSA() { }

			} dhe_rsa;

			struct { } rsa_dh_dss_dh_rsa_dhe_dss; /* KeyExchangeAlgorithm = RSA (1), DH_DSS (2), DH_RSA (3), DHE_DSS (4) */

			ServerExchangeKeys() { }
			~ServerExchangeKeys() { }

		} server_exchange_keys;

		ServerKeyExchange() : key_exchange_algorithm(DHE_RSA), server_exchange_keys(){ }
		~ServerKeyExchange() { }
	};

	struct CertificateRequest {
		std::vector<ClientCertificateType> certificate_types; // Represents ClientCertificateType certificate_types<1..2^8-1>;
		std::vector<DistinguishedName> certificate_authorities; // Represents DistinguishedName certificate_authorities<0..2^16-1>;

		CertificateRequest() : certificate_types(), certificate_authorities() { }
		~CertificateRequest() { }
	};

	struct ServerHelloDone { };

	struct PreMasterSecret {
		ProtocolVersion client_version;
		std::array<uint8_t, 46> random;

		PreMasterSecret() : client_version(), random() { }
		~PreMasterSecret() { }
	};

	struct EncryptedPreMasterSecret {
		//public-key-encrypted PreMasterSecret pre_master_secret;
		PreMasterSecret pre_master_secret;

		EncryptedPreMasterSecret() : pre_master_secret() { }
		~EncryptedPreMasterSecret() { }
	};

	struct ClientDiffieHellmanPublic {
		PublicValueEncoding public_value_encoding;
		union DhPublic{
			struct {} implicit; /* implicit encoding */
			std::vector<uint8_t> dh_Yc; /* explicit encoding */

			DhPublic() : implicit() {}
			~DhPublic() {}
		} dh_public;

		ClientDiffieHellmanPublic() { } 
		~ClientDiffieHellmanPublic() { }
	};

	struct ClientKeyExchange {
		KeyExchangeAlgorithm key_exchange_algorithm;
		union ClientExchangeKeys {
			EncryptedPreMasterSecret encryptedPreMasterSecret; /* KeyExchangeAlgorithm = RSA (1) */
			ClientDiffieHellmanPublic clientDiffieHellmanPublic; /* KeyExchangeAlgorithm = DH_ANON (6) */
			struct {} dhe_dss_dhe_rsa_dh_dss_dh_rsa; /* KeyExchangeAlgorithm = DHE_DSS (4), DHE_RSA (5), DH_DSS (2), DH_RSA (3) */

			ClientExchangeKeys() { }
			~ClientExchangeKeys() { }
		} client_exchange_keys;

		ClientKeyExchange() { }
		~ClientKeyExchange() { }
	};

	struct CertificateVerify {
		struct {
			std::vector<uint8_t> handshake_messages; /* Represents handshake_messages[handshake_messages_length]. */
		} digitally_signed;

		CertificateVerify() { }
		~CertificateVerify() { }
	};

	struct Finished {
		std::vector<uint8_t> verify_data;

		Finished() { }
		~Finished() { }
	};

	union Body { 				   
		HelloRequest helloRequest;
		ClientHello clientHello;
		ServerHello serverHello;
		Certificate certificate;
		ServerKeyExchange serverKeyExchange;
		CertificateRequest certificateRequest;
		ServerHelloDone serverHelloDone;
		CertificateVerify certificateVerify;
		ClientKeyExchange clientKeyExchange;
		Finished finished;

		void create(HandshakeType msg_type) {

			switch (msg_type) {
			case HELLO_REQUEST:
				helloRequest = { };
				break;
			case CLIENT_HELLO:
				new (&clientHello) ClientHello();
				break;
			case SERVER_HELLO:
				new (&serverHello) ServerHello();
				break;
			case CERTIFICATE:
				new (&certificate) Certificate();
				break;
			case SERVER_KEY_EXCHANGE:
				new (&serverKeyExchange) ServerKeyExchange();
				break;
			case CERTIFICATE_REQUEST:
				new (&certificateRequest) CertificateRequest();
				break;
			case SERVER_HELLO_DONE:
				serverHelloDone = { };
				break;
			case CERTIFICATE_VERIFY:
				new (&certificateVerify) CertificateVerify();
				break;
			case CLIENT_KEY_EXCHANGE:
				new (&clientKeyExchange) ClientKeyExchange();
				break;
			case FINISHED:
				new (&finished) Finished(); break;
			}
		}

		void destroy(HandshakeType msg_type) {
			switch (msg_type) {
			case HELLO_REQUEST:
				break;
			case CLIENT_HELLO:
				clientHello.~ClientHello();
				break;
			case SERVER_HELLO:
				serverHello.~ServerHello();
				break;
			case CERTIFICATE:
				certificate.~Certificate();
				break;
			case SERVER_KEY_EXCHANGE:
				serverKeyExchange.~ServerKeyExchange();
				break;
			case CERTIFICATE_REQUEST:
				certificateRequest.~CertificateRequest();
				break;
			case SERVER_HELLO_DONE:
				break;
			case CERTIFICATE_VERIFY:
				certificateVerify.~CertificateVerify();
				break;
			case CLIENT_KEY_EXCHANGE:
				clientKeyExchange.~ClientKeyExchange();
				break;
			case FINISHED: finished.~Finished();
				break;
			default: 
				break;
			}
		}

		Body() { }
		~Body() { }
	};

	struct Handshake {
		HandshakeType msg_type;    /* handshake type */
		uint32_t length;           /* bytes in message */ /***** Maybe needs to be uint16_t*/
		Body body;                 /* message contents */

		Handshake() : msg_type(HELLO_REQUEST), length(0) {
			body.create(HELLO_REQUEST);// By default, initial state
		} 
		~Handshake() {
			body.destroy(msg_type); // Pass msg_type to Body destructor
		}

		void updateBody() {
			body.create(msg_type); // Create a new body based on the current msg_type
		}
	};

/************************** Security Parameters *************************/

	/* The record layer will use the security parameters to generate the
	   following six items (some of which are not required by all ciphers,
	   and are thus empty):

		  client write MAC key
		  server write MAC key
		  client write encryption key
		  server write encryption key
		  client write IV
		  server write IV

		  SecurityParameters:											*/

	struct SecurityParameters {

		ConnectionEnd			entity;
		PRFAlgorithm			prf_algorithm;
		BulkCipherAlgorithm		bulk_cipher_algorithm;
		CipherType				cipher_type;
		uint8_t					enc_key_length;
		uint8_t					block_length;
		uint8_t					fixed_iv_length;
		uint8_t					record_iv_length;
		MACAlgorithm			mac_algorithm;
		uint8_t					mac_length;
		uint8_t					mac_key_length;
		CompressionMethod		compression_algorithm;
		std::array<uint8_t, 48> master_secret;
		std::array<uint8_t, 32> client_random;
		std::array<uint8_t, 32> server_random;
	};

} // namespace netlab
