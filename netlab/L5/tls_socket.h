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
    

    ~secure_socket() 
    {
        delete p_socket;
    }

   

protected:

    secure_socket(inet_os& inet) : L5_socket(inet), client_seq_num(0), server_seq_num(0)
    {
        p_socket = new L5_socket_impl(AF_INET, SOCK_STREAM, IPPROTO_TCP, inet);
    }

    secure_socket(inet_os& inet, L5_socket* p_sock) : L5_socket(inet), p_socket(p_sock), client_seq_num(0), server_seq_num(0)
    {

    }

    std::string encrypt(std::string& msg, bool server = false);

    std::string decrypt(std::string& msg, bool server = false);

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


    void extract_key(uint8_t * keyblock, size_t keyblock_len);

    int extract_public_key(const unsigned char* raw_cert, size_t raw_cert_len);

    std::vector<uint8_t> derrive_master_secret(std::vector<uint8_t> pre_master_vec, std::string client_rand, std::string server_rand);

    void derrive_keys(std::vector<uint8_t> master_secret, std::string client_rand, std::string server_rand);


    RSA* p_rsa;

    bool server;
};


}