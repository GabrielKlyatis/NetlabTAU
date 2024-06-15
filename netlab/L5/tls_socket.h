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
