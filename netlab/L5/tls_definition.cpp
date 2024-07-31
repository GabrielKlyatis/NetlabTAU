#include "tls_definition.hpp"

namespace netlab {

/************************************************************************/
/*                         The Cipher Suite                             */
/************************************************************************/

	const CipherSuite TLS_NULL_WITH_NULL_NULL = { 0x00, 0x00 };
	const CipherSuite TLS_RSA_WITH_NULL_MD5 = { 0x00, 0x01 };
	const CipherSuite TLS_RSA_WITH_NULL_SHA = { 0x00, 0x02 };
	const CipherSuite TLS_RSA_WITH_NULL_SHA256 = { 0x00, 0x3B };  
	const CipherSuite TLS_RSA_WITH_RC4_128_MD5 = { 0x00, 0x04 };
	const CipherSuite TLS_RSA_WITH_RC4_128_SHA = { 0x00, 0x05 };
	const CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0A };
	const CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x2F };
	const CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x35 };
	const CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x3C };
	const CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x3D };

	const CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0D };
	const CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x10 };
	const CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x13 };
	const CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x16 };
	const CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x30 };
	const CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x31 };
	const CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x32 };
	const CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x33 };
	const CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x36 };
	const CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x37 };
	const CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x38 };
	const CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x39 };
	const CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = { 0x00, 0x6A };
	const CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x6B };
	const CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = { 0x00, 0x6C };
	const CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x67 };
	const CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = { 0x00, 0x6E };
	const CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x6F };
	const CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = { 0x00, 0x6D };
	const CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x6B };


} // namespace netlab