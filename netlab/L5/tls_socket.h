#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/hmac.h>

#include "L5.h"
#include "tls_protocol_layer.hpp"
#pragma comment(lib, "Ws2_32.lib")

/************************************************************************/
/*                        Utility Functions                             */
/************************************************************************/

std::vector<uint8_t> get_certificate();
void rsa_decrypt(uint8_t decrypted_premaster_secret[MASTER_SECRET_SIZE], uint8_t encrypted[PRE_MASTER_SECRET_ENCRYPTED_SIZE]);

/************************************************************************/
/*                    secure_socket Class (Interface)                   */
/************************************************************************/

namespace netlab {

    // An abstract class used to define secure sockets.
    class secure_socket : public L5_socket {

    public:
		// Destructor - Implemented for you.
        ~secure_socket() {
            delete p_socket;
        }
  
    protected:

		// Constructor - Implemented for you.
        secure_socket(inet_os& inet) : L5_socket(inet), client_seq_num(0), server_seq_num(0) {
            p_socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet);
        }
        secure_socket(inet_os& inet, L5_socket* p_sock) : L5_socket(inet), p_socket(p_sock), client_seq_num(0), server_seq_num(0) { }

        /*
			encrypt Function - Encrypts the message using the encryption key and IV - Implemented for you.
			Parameters:
			    * msg - The message to be encrypted.
			    * server - A boolean indicating whether the message is from the server or not.
        */
        std::string encrypt(std::string& msg, bool server = false);

        /*
			decrypt Function - Decrypts the message using the encryption key and IV - Implemented for you.
			Parameters:
			    * msg - The message to be decrypted.
			    * server - A boolean indicating whether the message is from the server or not.
        */
        std::string decrypt(std::string& msg, bool server = false);

        /*
			prf Function - Pseudo-Random Function used to generate the keys - Implemented for you.
			Parameters:
			    * seed - The seed used to generate the keys.
			    * label - The label used to generate the keys.
			    * secret - The secret used to generate the keys.
			    * res - The result of the PRF.
			    * res_len - The length of the result.
        */
        void prf(std::vector<uint8_t>& seed, std::string label, std::vector<uint8_t>& secret, unsigned char* res, size_t res_len);

        L5_socket* p_socket;

        uint64_t client_seq_num;
        uint64_t server_seq_num;

        unsigned char client_write_MAC[MAC_KEY_SIZE];   // MAC key size (SHA-1)
        unsigned char server_write_MAC[MAC_KEY_SIZE];   // MAC key size (SHA-1)
        unsigned char client_write_key[ENCRYPTION_KEY_SIZE];   // Encryption key size (AES-128)
        unsigned char server_write_key[ENCRYPTION_KEY_SIZE];   // Encryption key size (AES-128)
        unsigned char client_write_IV[IV_KEY_SIZE];    // IV size
        unsigned char server_write_IV[IV_KEY_SIZE];    // IV size
    };

    /************************************************************************/
    /*                    tls_socket Class (Implementation)                 */
    /************************************************************************/

    class tls_socket : public secure_socket
    {
    public:

		// Constructor
        tls_socket(inet_os& inet, bool server = false);
        tls_socket(inet_os& inet, L5_socket* p_sock, bool server = false) : secure_socket(inet, p_sock), server(server) {}

		// Destructor
        ~tls_socket();

        /*
			bind Function - Binds the socket to the address - Implemented for you.
			Parameters:
			    * addr - The address to bind to.
			    * addr_len - The length of the address.
        */
        void bind(_In_ const struct sockaddr* addr, _In_ int addr_len) override;

        /*
			listen Function - Listens to the socket - Implemented for you.
			Parameters:
			    * backlog - The number of connections that can be queued.
        */
        void listen(_In_ int backlog) override;

        /*
			accept Function - Accepts a connection - Implemented for you.
			Parameters:
			    * addr - The address of the connection.
			    * addr_len - The length of the address.
        */
        L5_socket* accept(_Out_ struct sockaddr* addr, _Inout_ int* addr_len) ;

        /*
            connect Function -  
                Establishes a secure TLS connection to a specified address. 
                This function performs the following steps:
				1. Establishes a TCP connection to the specified address (using the connect function of the L5_socket_impl class).
                2. Initiates the TLS handshake process by sending a ClientHello message.
				3. Receives a ServerHello message from the server, along with the server's certificate and ServerHelloDone message.
				4. Extracts the server's public key from the certificate and verifies the certificate.
				5. Client key exchange: Generates a pre-master secret, encrypts it using the server's public key, and sends it to the server.
				6. Sends a ChangeCipherSpec message to indicate that the client is ready to switch to the negotiated cipher suite.
				7. Completes the handshake process by exchanging Finished messages with the server.

            Parameters:
            * name - The address to connect to.
            * name_len - The length of the address.
        */
        void connect(_In_ const struct sockaddr* name, _In_ int name_len) override;

        /*
            handshake Function - 
			Performs the TLS handshake process to establish a secure connection. 
            This process includes the following steps:
			1. Receiving a ClientHello message from the client, which includes the client's supported cipher suites and TLS version.
			2. Begins to create a buffer to store the handshake messages - ServerHello, Certificate, ServerHelloDone.
			3. Creates the ServerHello message, which includes the selected cipher suite, TLS version, and server random value 
            - and adds it to the buffer.
			4. Creates the Certificate message, which includes the server's certificate - and adds it to the buffer.
			5. Creates the ServerHelloDone message - and adds it to the buffer.
			6. Sends the buffer to the client.
			7. Receives the ClientKeyExchange message from the client, which includes the pre-master secret encrypted with the server's public key.
			8. Decrypts the pre-master secret using the server's private key.
			9. Derives the master secret from the pre-master secret and the client and server random values.
			10. Derives the keys from the master secret and the client and server random values.
			11. Sends a ChangeCipherSpec message to indicate that the server is ready to switch to the negotiated cipher suite.
			12. Completes the handshake process by exchanging Finished messages with the client.
        */
        void handshake();

		/*
			shutdown Function - Shuts down the socket.
			Parameters:
			    * how - The type of shutdown to perform.
		*/
        void shutdown(_In_ int how = SD_BOTH) override;

        /*
			send Function - Sends a message to the TLS socket 
            (Uses the send function of the L5_socket_impl class inside) - Implemented for you.
			Parameters:
			    * uio - The message to send.
			    * uio_resid - The length of the message.
			    * chunk - The size of the message chunk.
			    * flags - The flags to use.
        */
        void send(std::string uio, size_t uio_resid, size_t chunk, int flags) override;

        /*
			recv Function - Receives a message from the TLS socket 
            (Uses the recv function of the L5_socket_impl class inside) - Implemented for you.
			Parameters:
			    * uio - The message to receive.
			    * uio_resid - The length of the message.
			    * chunk - The size of the message chunk.
			    * flags - The flags to use.
        */
        int recv(std::string& uio, size_t uio_resid, size_t chunk = 1024, int flags = MSG_WAITALL) override;

        /*
			so_upcall Function - Handles the upcall - Implemented for you.
			Parameters:
			    * arg - The upcall arguments.
			    * waitf - A boolean indicating whether to wait for the upcall.
        */
        void so_upcall(struct upcallarg* arg, int waitf) override {}

    protected:

        /*
			extract_key Function - Extracts the key from the key block  - Implemented for you.
			Parameters:
				* keyblock - The key block.
				* keyblock_len - The length of the key block.
        */
        void extract_key(uint8_t * keyblock, size_t keyblock_len);

        /*
			extract_public_key Function - Extracts the public key from the certificate - Implemented for you.
			Parameters:
			    * raw_cert - The certificate.
			    * raw_cert_len - The length of the certificate.
        */
        int extract_public_key(const unsigned char* raw_cert, size_t raw_cert_len);

        /*
			derive_master_secret Function - Derives the master secret from the pre-master secret and the client 
            and server random values - Implemented for you.
			Parameters:
			    * pre_master_vec - The pre-master secret.
			    * client_rand - The client random value.
			    * server_rand - The server random value.
        */
        std::vector<uint8_t> derive_master_secret(std::vector<uint8_t> pre_master_vec, std::string client_rand, std::string server_rand);

        /*
			derive_keys Function - Derives the keys from the master secret and the client and server random values - Implemented for you.
			Parameters:
			    * master_secret - The master secret.
			    * client_rand - The client random value.
			    * server_rand - The server random value.
        */
        void derive_keys(std::vector<uint8_t> master_secret, std::string client_rand, std::string server_rand);

        RSA* p_rsa;
        bool server;
    };
} // namespace netlab