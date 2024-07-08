#pragma once

#include "L5.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/hmac.h>
#include "tls_protocol_layer.hpp"
#pragma comment(lib, "Ws2_32.lib")

namespace netlab {

// abstract class to define secure sockets
class secure_socket : public L5_socket {
public:
    
    secure_socket(inet_os& inet) : L5_socket(inet)
    {
        // TODO: may move to tls_socket class, i dont want to force use of the specif implemnt
        p_socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet);
    }

    secure_socket(inet_os& inet, L5_socket* p_sock) : L5_socket(inet), p_socket(p_sock)
    {
        // TODO: may move to tls_socket class, i dont want to force use of the specif implemnt
       // p_socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet);
    }

    ~secure_socket() 
    {
        delete p_socket;
    }

    unsigned char client_write_MAC[20];   // MAC key size (SHA-1)
    unsigned char server_write_MAC[20];   // MAC key size (SHA-1)
    unsigned char client_write_key[16];   // Encryption key size (AES-128)
    unsigned char server_write_key[16];   // Encryption key size (AES-128)
    unsigned char client_write_IV[16];    // IV size
    unsigned char server_write_IV[16];    // IV size

    enum tls_connection_type
    {
        TLS_CONNECTION_TYPE_CHANGE_CIPHER_SPEC = 0x14,
        TLS_CONNECTION_TYPE_ALERT = 0x15,
        TLS_CONNECTION_TYPE_HANDSHAKE = 0x16,
        TLS_CONNECTION_TYPE_APPLICATION_DATA = 0x17,
 
    };

    enum tls_state
    {
        NONE,                // No TLS state yet
        HELLO_SENT,          // ClientHello or ServerHello message sent
        HELLO_RECEIVED,      // ClientHello or ServerHello message received
        KEY_EXCHANGE,        // Key exchange message sent/received
        CERTIFICATE_ST,         // Certificate message sent/received
        CERTIFICATE_VERIFY_ST,  // CertificateVerify message sent/received
        FINISHED_ST             // Finished message
    };


#pragma pack(push, 1) // Pack struct tightly without any padding

    struct tls_header {
        uint8_t type;             // Content Type (TLS_ContentType)
        uint16_t version;         // TLS Version (tls_version)
        uint16_t length;          // Length of the TLS record payload
    } ;

    // maybe define as union or as 32 bytes array or as describe here
    struct TLSRandom {
      //  uint32_t timestemp;
        uint8_t random_bytes[32]; // 28 bytes for random data
    };

    struct tls_certificate
    {
        HandshakeType msg_type; // Handshake message
        uint8_t length[3];          // Length of the handshake message
        uint8_t cert_length[3];     // Length of the certificate
        std::vector<uint8_t> cert;      // certificate vector

        tls_certificate() {};

        tls_certificate(char* raw) 
        {
            msg_type = (HandshakeType)raw[0];
			length[0] = raw[1];
			length[1] = raw[2];
			length[2] = raw[3];
			uint32_t len = (length[0] << 16) | (length[1] << 8) | length[2];
			cert_length[0] = raw[4];
			cert_length[1] = raw[5];
			cert_length[2] = raw[6];
			uint32_t cert_len = (cert_length[0] << 16) | (cert_length[1] << 8) | cert_length[2];
			cert = std::vector<uint8_t>(raw + 7, raw + 7 + cert_len);
        }
    };

    struct TLSHello {
        HandshakeType msg_type; // Handshake message
        uint8_t length[3];          // Length of the handshake message
        uint16_t tls_version; // highest version supported by the client
        TLSRandom random;       // 32 bytes of random data
        std::vector<uint8_t> session_id; // session id vector
        std::vector<uint16_t> cipher_suites; // cipher vector
        std::vector<uint8_t> compression_methods; // comp method length
        std::vector<uint16_t> extensions; // extantuion length

        TLSHello() {}
        TLSHello(char* raw_header)
        {
            char a[500];

            msg_type = (HandshakeType)raw_header[0];
			length[0] = raw_header[1];
			length[1] = raw_header[2];
			length[2] = raw_header[3];
            uint32_t len = (length[0] << 16) | (length[1] << 8) | length[2];
        //    memcpy(a, raw_header, len + 4);

            tls_version = ntohs(*(uint16_t*)(raw_header + 4));
            random = *(TLSRandom*)(raw_header + 6);

            auto session_id_len = (uint8_t)raw_header[38] ;
            session_id = std::vector<uint8_t>(raw_header + 39 , raw_header + 39 + session_id_len);
            cipher_suites = { ntohs(*(uint16_t*)(raw_header + 39 + session_id_len)) };
            compression_methods = { (uint8_t)raw_header[41 + session_id_len]};

        }

        std::string parse(bool server = false)
        {
            std::string str;
          //  length[2] += 10;
			str.append((char*)&msg_type, sizeof(HandshakeType));
			str.append((char*)&length, sizeof(length));
			str.append((char*)&tls_version, sizeof(uint16_t));
			str.append((char*)&random, sizeof(TLSRandom));

            // add sesion length
            uint8_t session_id_len = session_id.size();
            str.append((char*)&session_id_len, 1);

            if (session_id_len > 0)
			    str.append((char*)session_id.data(), session_id.size());

            // add cipher suites
            uint16_t cipher_suites_len = htons(cipher_suites.size() * 2);
            if (!server)
                str.append((char*)&cipher_suites_len, 2);
            if (cipher_suites_len > 0)
			    str.append((char*)cipher_suites.data(), cipher_suites.size() * 2);

            // add compression methods
            uint8_t compression_methods_len = compression_methods.size();
			str.append((char*)&compression_methods_len,1);
            if (compression_methods_len > 0)
                auto a = compression_methods.data();
			    str.append((char*)compression_methods.data(), compression_methods.size());
            
			// add extensions
                   
            //char ext[] = {0x00, 0x08, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01 };
            //str.append(ext, 10);

            return str;
        }

    };

    struct tls_key_exchanege_msg
    {
        HandshakeType msg_type; // Handshake message
        uint8_t length[3];          // Length of the handshake message
        std::string premaster; // key exchange data

        std::string parse()
        {
            std::string str;
			str.append((char*)&msg_type, sizeof(HandshakeType));
			str.append((char*)&length, sizeof(length) );
            uint16_t len = htons(premaster.size());
            str.append((char*)&len, 2);
			str.append(premaster);
			return str;

        }

    };

   

    // Restore the default packing
#pragma pack(pop)

    // Enum for Cipher Suites
    enum CipherSuite : uint16_t {
        // TLS 1.2 Cipher Suites
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
        // Add more cipher suites as needed
    };

    // Enum for Compression Methods
    enum CompressionMethod : uint8_t {
        // TLS 1.2 Compression Methods
        NULL_COMPRESSION = 0x00,
        // Add more compression methods as needed
    };

protected:

    virtual std::string encrypt(std::string& msg, bool server = false)  = 0;

    virtual std::string decrypt(std::string& msg, bool server = false)  = 0;

    L5_socket* p_socket;

};



class tls_socket : public secure_socket
{
public:

    tls_socket(inet_os& inet, bool server = false);
    tls_socket(inet_os& inet, L5_socket* p_sock, bool server = false) : secure_socket(inet, p_sock), server(server) {}
    ~tls_socket();

    void bind(_In_ const struct sockaddr* addr, _In_ int addr_len) override;

    void listen(_In_ int backlog) override;

    L5_socket* accept(_Out_ struct sockaddr* addr, _Inout_ int* addr_len) ;

    void connect(_In_ const struct sockaddr* name, _In_ int name_len) override;

    void handshake() ;

    void shutdown(_In_ int how = SD_BOTH) override;

    void send(std::string uio, size_t uio_resid, size_t chunk, int flags) override;

    int recv(std::string& uio, size_t uio_resid, size_t chunk = 1024, int flags = MSG_WAITALL) override;

    void so_upcall(struct upcallarg* arg, int waitf) override {}

protected:

    std::string encrypt(std::string& msg, bool server = false) override;

    std::string decrypt(std::string& msg, bool server = false) override;

    void prf(std::vector<uint8_t> & seed, std::string label, std::vector<uint8_t> & secret, unsigned char* res, size_t res_len);

    void extract_key(uint8_t * keyblock, size_t keyblock_len);

    std::string get_raw_certificate(const char* cert_file) const ;

    std::vector < uint16_t> get_cipher_suites() const;

    int extract_public_key(const unsigned char* raw_cert, size_t raw_cert_len);

    std::vector<uint8_t> extract_master_secret(const std::vector<uint8_t>& preMasterSecret, const std::vector<uint8_t>& clientRandom,  const std::vector<uint8_t>& serverRandom);

    RSA* p_rsa;

    L5_socket* sock;

    uint64_t client_seq_num;
    uint64_t server_seq_num;

    bool server;
};


}