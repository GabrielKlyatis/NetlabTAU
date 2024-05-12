#pragma once

#include "./L5.h"

#include "openssl/ssl3.h"
#include "openssl/asn1err.h"


using namespace netlab;

class secure_socket : public L5_socket {
	
public:
	L5_socket* socket;


	/* Encryption Algorithms - Specifies the algorithms used for encrypting and decrypting the data. */

	/* Session Keys - Temporary encryption keys used for the duration of a session to ensure secure communication. */

	/* Certificates - Used to authenticate the identity of the parties. This includes a public key and the identity of the certificate authority that issued it. */

	/* Handshake Protocol - A procedure to negotiate the security attributes like the encryption algorithm and session keys. */

	/* Record Protocol - Defines how data is packaged and exchanged securely. */

	/*  Security Parameters - These are established during the handshake and include cryptographic algorithms, session identifiers, and master secrets. */

	/* Alert Protocol - Used to convey alerts to the peer about errors or issues in the session. */
};