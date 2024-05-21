//#include "tls_socket.h"
//#include <iostream>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <random>
//
//using namespace netlab;
//
//void generateRandomData(uint8_t* data, int size) {
//    // Create a random number generator engine
//    std::random_device rd;
//    std::mt19937 gen(rd());
//    std::uniform_int_distribution<uint16_t> dis(0, 255); // Use uint16_t
//
//    // Fill the array with random bytes
//    for (int i = 0; i < size; ++i) {
//        data[i] = static_cast<uint8_t>(dis(gen)); // Cast to uint8_t
//    }
//}
//
//
//
//tls_socket::tls_socket(inet_os& inet) : secure_socket(inet) {
//    // TODO: Implement TLS socket constructor
//    SSL_library_init();
//
//    
//  //  SSL_CTX_free(ctx);
//
//}
//
//tls_socket::~tls_socket() {
//    // TODO: Implement TLS socket destructor
//
//}
//
//std::vector<uint16_t> tls_socket::get_cipher_suites() const
//{
//    std::vector<uint16_t> cipher_suites;
//    // Create a new SSL context
//    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
//    // Set TLS 1.2 as the minimum and maximum protocol version
//    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
//    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
//
//
//    // Get the list of supported cipher suites
//    const SSL_METHOD* ciphers_method = SSL_CTX_get_ssl_method(ctx);
//
//    SSL* ssl = SSL_new(ctx);
//
//    // Get the supported cipher suites
//    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);
//
//
//    // Print the list of supported cipher suites
//    //std::cout << "Supported Cipher Suites:" << std::endl;
//    int counter = 0;
//    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
//        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
//        const char* name = SSL_CIPHER_get_name(cipher);
//        uint16_t value = SSL_CIPHER_get_id(cipher);
//        cipher_suites.push_back(htons(value));
//        if (cipher_suites.size() >= 30) {
//			break;
//		}
//        if (name) {
//            // std::cout << name << std::hex <<  "\t value:    " << value << std::endl;
//        }
//        counter++;
//    }
//    //std::cout << std::dec << "Total number of supported cipher suites: " << counter << std::endl;
//    // Clean up
//    sk_SSL_CIPHER_free(ciphers);
//    SSL_free(ssl);
//
//    return cipher_suites;
//}
//
//void tls_socket::bind(const struct sockaddr* addr, int addr_len) {
//    p_socket->bind(addr, addr_len);
//}
//
//void tls_socket::listen(int backlog) {  
//    p_socket->listen(backlog);
//   
//}
//
//L5_socket* tls_socket::accept(struct sockaddr* addr, int* addr_len) {
//    
//
//
//    return nullptr;
//}
//
//void tls_socket::connect(const struct sockaddr* name, int name_len) {
//    
//    // first establish tcp connection
//    p_socket->connect(name, name_len);
//
//
//    std::cout << "finish ttcp hanshke" << std::endl;
//
//    // send client hello
//    tls_header header;
//    header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
//    header.version = htons(TLS_VERSION_TLSv1_0);
//        
//    // init client hello msg
//    TLSHello client_msg;    
//    client_msg.msg_type = CLIENT_HELLO;
//
//    client_msg.tls_version = htons(TLS_VERSION_TLSv1_2);
//    
//    // set random bytes
//    generateRandomData(client_msg.random.random_bytes, 32);
//
//    client_msg.session_id = {};
//   
//    client_msg.cipher_suites = get_cipher_suites();
//
//    
//    client_msg.compression_methods = { NULL_COMPRESSION };
//
//    client_msg.extensions = {};
//
//    // set header length
//    
//    
//    uint32_t msg_len = sizeof(TLSHello) - 3;
//    client_msg.length[0] = (msg_len >> 16) & 0xFF;
//    client_msg.length[1] = (msg_len >> 8) & 0xFF;
//    client_msg.length[2] = msg_len & 0xFF;
//    
//    
//
//    // create a buffer to store the client hello msg
//    std::string buffer;
//   
//    std::string msg_to_send = client_msg.parse();
//    uint16_t total_length = msg_to_send.size();
//    header.length = htons(total_length);
//    buffer.append((char*)&header, sizeof(tls_header));
//    buffer.append(msg_to_send);
//
//
//    // send client hello msg
//
//    std::cout << "sizeof header" << sizeof(tls_header) << std::endl;
//    std::cout << "sizeof client msg" << msg_to_send.size() << std::endl;
//
//    p_socket->send(buffer, buffer.size(), 0, 0);
//
//
//
//    std::cout << "finish send client hello" << std::endl;
//
//
//    
//
//
//   
//
//}
//
//void tls_socket::shutdown(int how) {
//    // TODO: Implement shutdown method for TLS socket
//}
//
//void tls_socket::send(std::string uio, size_t uio_resid, size_t chunk, int flags) {
//    // TODO: Implement send method for TLS socket
//}
//
//int tls_socket::recv(std::string& uio, size_t uio_resid, size_t chunk, int flags) {
//    // TODO: Implement recv method for TLS socket
//    return 0;
//}
//
//std::string tls_socket::encrypt(std::string& msg) const {
//    // TODO: Implement encryption method for TLS socket
//    return "";
//}
//
//std::string tls_socket::decrypt(std::string& msg) const {
//    // TODO: Implement decryption method for TLS socket
//    return "";
//}
//
//
