#pragma once

#include "tls_utils.hpp"
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

#pragma pack(push, 1) // Pack struct tightly without any padding

	struct tls_header {
		uint8_t type;             // Content Type (TLS_ContentType)
		uint16_t version;         // TLS Version (tls_version)
		uint16_t length;          // Length of the TLS record payload
	};


#pragma pack(pop)

	enum tls_version
	{
	    TLS_VERSION_SSLv3 = 0x0300,
	    TLS_VERSION_TLSv1_0 = 0x0301,
	    TLS_VERSION_TLSv1_1 = 0x0302,
	    TLS_VERSION_TLSv1_2 = 0x0303,
	    TLS_VERSION_TLSv1_3 = 0x0304,

	};

#define RANDOM_BYTES_SIZE 28
#define SESSION_ID_SIZE 32
#define PRE_MASTER_SECRET_RND_SIZE 46
#define PRE_MASTER_SECRET_ENCRYPTED_SIZE 256
#define MASTER_SECRET_SIZE 48
#define KEY_BLOCK_SIZE 104
#define SHA256_HASH_LEN 32
#define VERIFY_DATA_LEN 12
#define ENCRYPTION_KEY_SIZE 16
#define IV_KEY_SIZE 16
#define MAC_KEY_SIZE 20

#define RECORD_LAYER_DEFAULT_LENGTH 5
#define SERVER_DONE_RECORD_LAYER_LENGTH 4
#define CHANGE_CIPHER_SPEC_RECORD_LAYER_LENGTH 1

#define HANDSHAKE_RECORD_LAYER_OFFSET_LENGTH 4
#define CERTIFICATE_HANDSHAKE_OFFSET_LENGTH 3

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

	static CipherSuite TLS_NULL_WITH_NULL_NULL = { 0x00,0x00 };
	static CipherSuite TLS_EMPTY_RENEGOTIATION_INFO_SCSV = { 0x00,0xFF };
	static CipherSuite TLS_RSA_WITH_NULL_MD5 = { 0x00,0x01 };
	static CipherSuite TLS_RSA_WITH_NULL_SHA = { 0x00,0x02 };
	static CipherSuite TLS_RSA_WITH_NULL_SHA256 = { 0x00,0x3B };
	static CipherSuite TLS_RSA_WITH_RC4_128_MD5 = { 0x00,0x04 };
	static CipherSuite TLS_RSA_WITH_RC4_128_SHA = { 0x00,0x05 };
	static CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x0A };
	static CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x2F };
	static CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x35 };
	static CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3C };
	static CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x3D };

	/* The following cipher suite definitions are used for server-
	   authenticated (and optionally client-authenticated) Diffie-Hellman. */
	
	static CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00,0x0D };
	static CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x10 };
	static CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00,0x13 };
	static CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00,0x16 };
	static CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA = { 0x00,0x30 };
	static CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x31 };
	static CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA = { 0x00,0x32 };
	static CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA = { 0x00,0x33 };
	static CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA = { 0x00,0x36 };
	static CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x37 };
	static CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA = { 0x00,0x38 };
	static CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA = { 0x00,0x39 };
	static CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,0x3E };
	static CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3F };
	static CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,0x40 };
	static CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x67 };
	static CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,0x68 };
	static CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x69 };
	static CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,0x6A };
	static CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x6B };

	/* The following cipher suites are used for completely anonymous
	   Diffie-Hellman communications in which neither party is
	   authenticated. */

	static CipherSuite TLS_DH_anon_WITH_RC4_128_MD5 = { 0x00,0x18 };
	static CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = { 0x00,0x1B };
	static CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA = { 0x00,0x34 };
	static CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA = { 0x00,0x3A };
	static CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256 = { 0x00,0x6C };
	static CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256 = { 0x00,0x6D };

/************************************************************************/
/*								  enums                                 */
/************************************************************************/

/**************************** TLS Record Layer **************************/

	enum ContentType : uint8_t {

		TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14,
		TLS_CONTENT_TYPE_ALERT = 0x15,
		TLS_CONTENT_TYPE_HANDSHAKE = 0x16,
		TLS_CONTENT_TYPE_APPLICATION_DATA = 0x17,
		TLS_CONTENT_TYPE_MAX_VALUE = 255,
	};


/************************** Change Cipher Spect ************************/

	enum Type : uint8_t {
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
		HashAlgorithm_SHA256 = 4,
		SHA384 = 5,
		SHA512 = 6,
		HASH_ALGORITHM_MAX_VALUE = 255,
	} ;

	enum SignatureAlgorithm {
		ANONYMOUS = 0,
		SIGNATURE_ALGORITHM_RSA = 1,
		DSA = 2,
		ECDSA = 3,
		SIGNATURE_ALGORITHM_MAX_VALUE = 255,
	};

	enum KeyExchangeAlgorithm : uint8_t {
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

			Fragment() : streamCipher(), blockCipher(), aeadCipher() { }
			~Fragment() { }
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
		std::array<uint8_t, RANDOM_BYTES_SIZE> random_bytes;

		Random() : gmt_unix_time(0), random_bytes() { }

		Random(uint32_t gmt_unix_time, std::array<uint8_t, RANDOM_BYTES_SIZE> random_bytes)
			: gmt_unix_time(gmt_unix_time), random_bytes(random_bytes) { }

		std::string get_random()
		{
			std::string st;
			st.push_back((gmt_unix_time >> 24) & 0xff);
			st.push_back((gmt_unix_time >> 16) & 0xff);
			st.push_back((gmt_unix_time >> 8) & 0xff);
			st.push_back(gmt_unix_time & 0xff);
			
			
		//	serialize_4_bytes(st, gmt_unix_time);
			st.append((char*)random_bytes.data(), RANDOM_BYTES_SIZE);
			return st;
		}

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

		/* Constructor */
		ClientHello()
			: client_version{ 3, 3 },
			random{ 0, {} },
			session_id{},
			cipher_suites{ TLS_RSA_WITH_AES_128_CBC_SHA , TLS_EMPTY_RENEGOTIATION_INFO_SCSV },
			compression_methods{ NULL_COMPRESSION, COMPRESSION_METHOD_MAX_VALUE },
			extensions_present(false),
			extensions_union{}
		{ }

		void setClientHello() {

			random.gmt_unix_time = static_cast<uint32_t>(time(0));
			random.random_bytes = generate_random_bytes<RANDOM_BYTES_SIZE>();
			//session_id = generate_random_bytes<SESSION_ID_SIZE>();
		}

		uint16_t getClientHelloSize() {
			uint16_t clientHelloSize = 0;
			clientHelloSize += sizeof(client_version);
			clientHelloSize += sizeof(random.gmt_unix_time);
			clientHelloSize += RANDOM_BYTES_SIZE;
			clientHelloSize += 1; // 1 byte of SessionID length.
			if (!(std::all_of(session_id.begin(), session_id.end(), [](uint8_t byte) { return byte == 0; }))) {
				clientHelloSize += SESSION_ID_SIZE; // 32 bytes of SessionID.
			}
			clientHelloSize += sizeof(uint16_t); // 2 bytes of cipher_suites length.
			clientHelloSize += cipher_suites.size() * sizeof(CipherSuite);
			clientHelloSize += sizeof(uint8_t); // 1 byte of compression_methods length.
			clientHelloSize += compression_methods.size() * sizeof(CompressionMethod);
			if (extensions_present) {
				clientHelloSize += sizeof(uint16_t); // 2 bytes of extensions length.
				for (auto& extension : extensions_union.extensions) {
					clientHelloSize += sizeof(extension.extension_type);
					clientHelloSize += sizeof(uint16_t); // 2 bytes of extension_data length.
					clientHelloSize += extension.extension_data.size();
				}
			}
			else {
				clientHelloSize += 2; // 2 bytes of extensions length.
			}
			return clientHelloSize;
		}

	};

	struct ServerHello {
		ProtocolVersion server_version;
		Random random;
		SessionID session_id;
		CipherSuite cipher_suite;
		CompressionMethod compression_method;
		bool extensions_present;
		ExtensionUnion extensions_union;

		/* Constructor */
		ServerHello()
			: server_version{ 3, 3 },
			random{ 0, {} },
			session_id{},
			cipher_suite(TLS_RSA_WITH_AES_128_CBC_SHA),
			compression_method{ NULL_COMPRESSION },
			extensions_present(false),
			extensions_union{}
		{ }

		void setServerHello() {
			random.gmt_unix_time = static_cast<uint32_t>(time(0));
			random.random_bytes = generate_random_bytes<RANDOM_BYTES_SIZE>();
			session_id = generate_random_bytes<SESSION_ID_SIZE>();
		}

		uint16_t getServerHelloSize() {
			uint16_t serverHelloSize = 0;
			serverHelloSize += sizeof(server_version);
			serverHelloSize += sizeof(random.gmt_unix_time);
			serverHelloSize += RANDOM_BYTES_SIZE;
			serverHelloSize += sizeof(uint8_t); // 1 byte of SessionID length.
			if (!is_all_zeros_array(session_id)) {
				serverHelloSize += SESSION_ID_SIZE; // 32 bytes of SessionID.
			}
			serverHelloSize += sizeof(cipher_suite);
			serverHelloSize += sizeof(compression_method);
			if (extensions_present) {
				serverHelloSize += sizeof(uint16_t); // 2 bytes of extensions length.
				for (auto& extension : extensions_union.extensions) {
					serverHelloSize += sizeof(extension.extension_type);
					serverHelloSize += sizeof(uint16_t); // 2 bytes of extension_data length.
					serverHelloSize += extension.extension_data.size();
				}
			}
			else {
				serverHelloSize += 2; // 2 bytes of extensions length.
			}
			return serverHelloSize;
		}
	};

	struct SignatureAndHashAlgorithm {
		HashAlgorithm hash;
		SignatureAlgorithm signature;
	};

	struct Certificate {
		std::vector<std::vector<uint8_t>> certificate_list; /* Represents ASN.1Cert certificate_list<0..2 ^ 24 - 1>. */
		Certificate() : certificate_list() { }

		void addCertificate(const std::vector<uint8_t>& certificate) {
			certificate_list.push_back(certificate);
		}
	};

	struct ServerDHParams {
		std::vector<uint8_t> dh_p;
		std::vector<uint8_t> dh_g;
		std::vector<uint8_t> dh_Ys;

		ServerDHParams() : dh_p(), dh_g(), dh_Ys() { }
	};

	struct ServerKeyExchange {
		KeyExchangeAlgorithm key_exchange_algorithm;
		union ServerExchangeKeys{
			struct dhANON {
				ServerDHParams params;

				dhANON() : params() { }

			} dh_anon; /* KeyExchangeAlgorithm = DH_ANON (6)*/

			struct dheRSA{ /* KeyExchangeAlgorithm = DHE_RSA (5) */
				ServerDHParams params;
				struct SignedParams{
					Random client_random;
					Random server_random;
					ServerDHParams params;

					SignedParams() : client_random(), server_random(), params() { }

				} signed_params;

				dheRSA() : params(), signed_params() { }

			} dhe_rsa;

			struct { } rsa_dh_dss_dh_rsa_dhe_dss; /* KeyExchangeAlgorithm = RSA (1), DH_DSS (2), DH_RSA (3), DHE_DSS (4) */

			ServerExchangeKeys() { }
			~ServerExchangeKeys() { }

		} server_exchange_keys;

		void createServerKeyExchange() {
			switch (key_exchange_algorithm) {
			case DHE_RSA:
				new (&server_exchange_keys.dhe_rsa) ServerExchangeKeys::dheRSA();
				break;
			case DH_ANON:
				new (&server_exchange_keys.dh_anon) ServerExchangeKeys::dhANON();
				break;
			default:
				break;
			}
		}

		ServerKeyExchange() : key_exchange_algorithm(DHE_RSA), server_exchange_keys(){ }
	};

	struct CertificateRequest {
		std::vector<ClientCertificateType> certificate_types; // Represents ClientCertificateType certificate_types<1..2^8-1>;
		std::vector<DistinguishedName> certificate_authorities; // Represents DistinguishedName certificate_authorities<0..2^16-1>;

		CertificateRequest() : certificate_types(), certificate_authorities() { }
	};

	struct ServerHelloDone { };

	struct PreMasterSecret {
		ProtocolVersion client_version;
		std::array<uint8_t, PRE_MASTER_SECRET_RND_SIZE> random;

		PreMasterSecret() : client_version({ 3, 3 }), random(generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>()) { }
	};

	struct EncryptedPreMasterSecret {
		PreMasterSecret pre_master_secret;
		std::array<uint8_t, PRE_MASTER_SECRET_ENCRYPTED_SIZE> encrypted_pre_master_secret;
		EncryptedPreMasterSecret() : encrypted_pre_master_secret() { }
	};

	struct ClientDiffieHellmanPublic {
		PublicValueEncoding public_value_encoding;
		union DhPublic{
			struct {} implicit; /* implicit encoding */
			std::vector<uint8_t> dh_Yc; /* explicit encoding */

			DhPublic() : implicit() {}
			~DhPublic() {}
		} dh_public;

		void createClientDiffieHellmanPublic() {
			switch (public_value_encoding) {
			case IMPLICIT:
				break;
			case EXPLICIT:
				new (&dh_public.dh_Yc) std::vector<uint8_t>();
				break;
			default:
				break;
			}
		}
	};

	struct ClientKeyExchange {
		KeyExchangeAlgorithm key_exchange_algorithm;
		union ClientExchangeKeys {
			EncryptedPreMasterSecret encryptedPreMasterSecret; /* KeyExchangeAlgorithm = KEY_EXCHANGE_ALGORITHM_RSA (1) */
			ClientDiffieHellmanPublic clientDiffieHellmanPublic; /* KeyExchangeAlgorithm = DH_ANON (6) */
			struct {} dhe_dss_dhe_rsa_dh_dss_dh_rsa; /* KeyExchangeAlgorithm = DHE_DSS (4), DHE_RSA (5), DH_DSS (2), DH_RSA (3) */

			ClientExchangeKeys() { }
			~ClientExchangeKeys() { }
		} client_exchange_keys;

		void createClientKeyExchange() {
			switch (key_exchange_algorithm) {
			case KEY_EXCHANGE_ALGORITHM_RSA:
				new (&client_exchange_keys.encryptedPreMasterSecret) EncryptedPreMasterSecret();
				break;
			case DH_ANON:
				new (&client_exchange_keys.clientDiffieHellmanPublic) ClientDiffieHellmanPublic();
				break;
			default:
				break;
			}
		}

		ClientKeyExchange() : key_exchange_algorithm(KEY_EXCHANGE_ALGORITHM_RSA), client_exchange_keys() { }

		void setClientKeyExchange() {
			client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version = { 3, 3 };
			client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>();
		}

		uint16_t getClientKeyExchangeSize() {
			uint16_t clientKeyExchangeSize = 0;
			switch (key_exchange_algorithm) {
			case KEY_EXCHANGE_ALGORITHM_RSA:
				clientKeyExchangeSize += 2; // 2 bytes of pre_master_secret length.
				clientKeyExchangeSize += PRE_MASTER_SECRET_ENCRYPTED_SIZE;
				break;
			case DH_ANON:
				clientKeyExchangeSize += sizeof(client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding);
				if (client_exchange_keys.clientDiffieHellmanPublic.public_value_encoding == EXPLICIT) {
					clientKeyExchangeSize += sizeof(uint16_t); // 2 bytes of dh_Yc length.
					clientKeyExchangeSize += client_exchange_keys.clientDiffieHellmanPublic.dh_public.dh_Yc.size();
				}
				break;
			default:
				break;
			}
			return clientKeyExchangeSize;
		}
	};

	struct CertificateVerify {
		struct {
			std::vector<uint8_t> handshake_messages; /* Represents handshake_messages[handshake_messages_length]. */
		} digitally_signed;
	};

	struct Finished {
		std::vector<uint8_t> verify_data;
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

		void createBody(HandshakeType msg_type) {

			switch (msg_type) {
			case HELLO_REQUEST:
				helloRequest = { };
				break;
			case CLIENT_HELLO:
				new (&clientHello) ClientHello();
				clientHello.setClientHello();
				break;
			case SERVER_HELLO:
				new (&serverHello) ServerHello();
				serverHello.setServerHello();
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
				clientKeyExchange.setClientKeyExchange();
				break;
			case FINISHED:
				new (&finished) Finished(); break;
			}
		}

		void destroy(HandshakeType msg_type) {
			/*switch (msg_type) {
			case HELLO_REQUEST:
				break;
			case CLIENT_HELLO:
				delete &clientHello;
				break;
			case SERVER_HELLO:
				delete &serverHello;
				break;
			case CERTIFICATE:
				delete &certificate;
				break;
			case SERVER_KEY_EXCHANGE:
				delete &serverKeyExchange;
				break;
			case CERTIFICATE_REQUEST:
				delete &certificateRequest;
				break;
			case SERVER_HELLO_DONE:
				break;
			case CERTIFICATE_VERIFY:
				delete &certificateVerify;
				break;
			case CLIENT_KEY_EXCHANGE:
				delete &clientKeyExchange;
				break;
			case FINISHED:
				delete &finished;
				break;
			default: 
				break;
			}*/
		}

		Body() { }
		~Body() { }
	};

	struct Handshake {
		HandshakeType msg_type;    /* handshake type */
		uint32_t length;           /* bytes in message - 24 bits */
		Body body;                 /* message contents */

		Handshake(HandshakeType msg_type, uint32_t length)
			: msg_type(msg_type), length(length) {
			body.createBody(msg_type);
		}

		~Handshake() {
			body.destroy(msg_type); // Pass msg_type to Body destructor
		}

		void configureHandshakeBody(HandshakeType passed_msg_type) {
			this->msg_type = passed_msg_type;
			body.createBody(msg_type); // Create a new body based on the current msg_type
		}

		void updateHandshakeLength(HandshakeType passed_msg_type) {

			switch (passed_msg_type) {
				// Update the length of the message
			case HELLO_REQUEST:
				this->length = 0;
				break;
			case CLIENT_HELLO:
				this->length = body.clientHello.getClientHelloSize();
				break;
			case SERVER_HELLO:
				this->length = body.serverHello.getServerHelloSize();
				break;
			case CERTIFICATE:
				this->length = this->body.certificate.certificate_list.data()->size() + CERTIFICATE_HANDSHAKE_OFFSET_LENGTH * 2;
				break;
			case SERVER_KEY_EXCHANGE:
				break;
			case CERTIFICATE_REQUEST:
				break;
			case SERVER_HELLO_DONE:
				this->length = 0;
				break;
			case CERTIFICATE_VERIFY:
				break;
			case CLIENT_KEY_EXCHANGE:
				this->length = this->body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.size();
				this->length += sizeof(uint16_t);
				break;
			case FINISHED:
				break;
			}
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

	SecurityParameters:													*/

	struct SecurityParameters {

		ConnectionEnd								entity;
		PRFAlgorithm								prf_algorithm;
		BulkCipherAlgorithm							bulk_cipher_algorithm;
		CipherType									cipher_type;
		uint8_t										enc_key_length;
		uint8_t										block_length;
		uint8_t										fixed_iv_length;
		uint8_t										record_iv_length;
		MACAlgorithm								mac_algorithm;
		uint8_t										mac_length;
		uint8_t										mac_key_length;
		CompressionMethod							compression_algorithm;
		std::array<uint8_t, MASTER_SECRET_SIZE>		master_secret;
		Random										client_random;
		Random										server_random;
	};

} // namespace netlab
