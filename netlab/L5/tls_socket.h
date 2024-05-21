#pragma once

#include "L5.h"
#include "tls_definition.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

namespace netlab {

// abstract class to define secure sockets
class secure_socket : public L5_socket {
public:
    
    secure_socket(inet_os& inet) : L5_socket(inet)
    {
        // TODO: may move to tls_socket class, i dont want to force use of the specif implemnt
        p_socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet);
    }

    ~secure_socket() 
    {
        delete p_socket;
    }


#pragma pack(push, 1) // Pack struct tightly without any padding

    

    struct TLSHello {
        HandshakeType msg_type; // Handshake message
        uint8_t length[3];          // Length of the handshake message
        uint16_t tls_version; // highest version supported by the client
        Random random;       // 32 bytes of random data
        std::vector<uint8_t> session_id; // session id vector
        std::vector<uint16_t> cipher_suites; // cipher vector
        std::vector<uint8_t> compression_methods; // comp method length
        std::vector<uint8_t> extensions; // extantuion length

        std::string parse()
        {
            std::string str;
			str.append((char*)&msg_type, sizeof(HandshakeType));
			str.append((char*)&length, sizeof(length));
			str.append((char*)&tls_version, sizeof(uint16_t));
			str.append((char*)&random, sizeof(Random));

            // add sesion length
            uint8_t session_id_len = session_id.size();
            str.append((char*)&session_id_len, 1);

            if (session_id_len > 0)
			    str.append((char*)session_id.data(), session_id.size());

            // add cipher suites
            uint16_t cipher_suites_len = htons(cipher_suites.size() * 2);
            str.append((char*)&cipher_suites_len, 2);
            if (cipher_suites_len > 0)
			    str.append((char*)cipher_suites.data(), cipher_suites.size() * 2);

            // add compression methods
            uint8_t compression_methods_len = compression_methods.size();
			str.append((char*)&compression_methods_len,1);
            if (compression_methods_len > 0)
                uint8_t* a = compression_methods.data();
			    str.append((char*)compression_methods.data(), compression_methods.size());
            
			// add extensions
            /*uint8_t extensions_len = extensions.size();
            str.append((char*)&extensions_len,1);
            if (extensions_len > 0)
                str.append((char*)extensions.data(), extensions.size());*/

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

    virtual std::string encrypt(std::string& msg) const = 0;

    virtual std::string decrypt(std::string& msg) const = 0;

    L5_socket* p_socket;

};



class TLSSocket : public secure_socket {
public:

    TLSSocket(inet_os& inet);
    ~TLSSocket();

    void bind(_In_ const struct sockaddr* addr, _In_ int addr_len) override;

    void listen(_In_ int backlog) override;

    L5_socket* accept(_Out_ struct sockaddr* addr, _Inout_ int* addr_len) override;

    void connect(_In_ const struct sockaddr* name, _In_ int name_len) override;

    void shutdown(_In_ int how = SD_BOTH) override;

    void send(std::string uio, size_t uio_resid, size_t chunk, int flags) override;

    int recv(std::string& uio, size_t uio_resid, size_t chunk = 1024, int flags = MSG_WAITALL) override;

    void so_upcall(struct upcallarg* arg, int waitf) override {}

protected:

    std::string encrypt(std::string& msg) const override;

    std::string decrypt(std::string& msg) const override;

    std::vector < uint16_t> get_cipher_suites() const;

private:
    SSL_CTX* ctx;
    SSL* ssl;
};

}
