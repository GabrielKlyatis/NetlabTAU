#include "tls_socket.h"
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <random>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/applink.c>

#include <stdio.h>
#include <stdint.h>


#pragma warning(disable : 4996)

#define VERIFY_DATA_LEN 12
#define AES_BLOCK_SIZE 16
#define HMAC_SHA1_LEN 20

using namespace netlab;

int tls_socket::extract_public_key(const unsigned char* raw_cert, size_t raw_cert_len) {
    // Create a BIO object from the TLS data
    // Initialize OpenSSL
    SSL_library_init();
    OPENSSL_init_ssl(0, NULL);
    OPENSSL_init_crypto(0, NULL);

    // Create a BIO object to read the certificate
    BIO* bio = BIO_new_mem_buf(raw_cert, raw_cert_len);
    if (!bio) {
        std::cerr << "Error creating BIO" << std::endl;
        return 1;
    }

    // Load the certificate
    X509* cert = d2i_X509_bio(bio, NULL);
    if (!cert) {
        std::cerr << "Error loading certificate" << std::endl;
        BIO_free(bio);
        return 1;
    }

    // Get the public key from the certificate
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        std::cerr << "Error extracting public key" << std::endl;
        X509_free(cert);
        BIO_free(bio);
        return 1;
    }

    // Extract the RSA public key
    if (EVP_PKEY_id(pubkey) != EVP_PKEY_RSA) {
        std::cerr << "Public key is not an RSA key" << std::endl;
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        BIO_free(bio);
        return 1;
    }

    p_rsa = EVP_PKEY_get1_RSA(pubkey);
    
    const BIGNUM* n, * e;
    RSA_get0_key(p_rsa, &n, &e, NULL);

    char* modulus_hex = BN_bn2hex(n);
    char* exponent_hex = BN_bn2hex(e);

    // Print modulus and exponent
    //std::cout << "Modulus: " << modulus_hex << std::endl;
   // std::cout << "Exponent: " << exponent_hex << std::endl;
    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free(bio);

    return 0;

}



tls_socket::tls_socket(inet_os& inet) : secure_socket(inet), client_seq_num(0), server_seq_num(0) {
    // TODO: Implement TLS socket constructor
    SSL_library_init();

    
  //  SSL_CTX_free(ctx);

}

tls_socket::~tls_socket() {
    // TODO: Implement TLS socket destructor

}

std::vector<uint16_t> tls_socket::get_cipher_suites() const
{
    std::vector<uint16_t> cipher_suites;
    // Create a new SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    // Set TLS 1.2 as the minimum and maximum protocol version
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    // Get the list of supported cipher suites
    const SSL_METHOD* ciphers_method = SSL_CTX_get_ssl_method(ctx);

    SSL* ssl = SSL_new(ctx);

    // Get the supported cipher suites
    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);

    // Print the list of supported cipher suites
    //std::cout << "Supported Cipher Suites:" << std::endl;
    int counter = 0;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
        const char* name = SSL_CIPHER_get_name(cipher);
        uint16_t value = SSL_CIPHER_get_id(cipher);
        cipher_suites.push_back(htons(value));
        if (cipher_suites.size() >= 30) {
			break;
		}
        counter++;
    }
    // Clean up
    sk_SSL_CIPHER_free(ciphers);
    SSL_free(ssl);
    return cipher_suites;
}

void tls_socket::bind(const struct sockaddr* addr, int addr_len) {
    p_socket->bind(addr, addr_len);
}

void tls_socket::listen(int backlog) {  
    p_socket->listen(backlog);
   
}



L5_socket* tls_socket::accept(struct sockaddr* addr, int* addr_len) {


    L5_socket* sock = p_socket->accept(addr, addr_len);

    // handle handshake
    std::string recv_buffer;
    recv_buffer.reserve(1500);
    int byte_recived = sock->recv(recv_buffer, 1500, 1, 0);

    // get client hello msg
    tls_header* recv_header = (tls_header*)recv_buffer.c_str();
    if (ntohs(recv_header->version) != TLS_VERSION_TLSv1_0)
    {
        return nullptr;
    }

    char* start_of_client_hello = (char*)recv_buffer.c_str() + sizeof(tls_header);
    TLSHello client_hello(start_of_client_hello);

    // verify the client hello msg

    // send server hello msg
    tls_header server_hello_header;
    server_hello_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    server_hello_header.version = htons(TLS_VERSION_TLSv1_2);
    server_hello_header.length = htons(74);

    uint32_t len = 70;

    TLSHello server_hello_msg;
    server_hello_msg.msg_type = SERVER_HELLO;
    server_hello_msg.tls_version = htons(TLS_VERSION_TLSv1_2);
    RAND_bytes(server_hello_msg.random.random_bytes, 32);

    uint8_t sid[32];
    RAND_bytes(sid, 32);
    server_hello_msg.session_id.insert(server_hello_msg.session_id.end(), sid, sid + 32);

    server_hello_msg.cipher_suites = { 0x2f00};
    
    server_hello_msg.length[0] = (len >> 16) & 0xFF;
    server_hello_msg.length[1] = (len >> 8) & 0xFF;
    server_hello_msg.length[2] = len & 0xFF;


    std::string server_hello_msg_raw = server_hello_msg.parse(true);

    std::string server_hello_buffer;
    server_hello_buffer.append((char*)&server_hello_header, sizeof(tls_header));
    server_hello_buffer.append(server_hello_msg_raw);


    const char* cert_file = "C:/Program Files/OpenSSL-Win64/server.crt";

   
    FILE* fp = fopen(cert_file, "r");
    if (!fp) {
        fprintf(stderr, "unable to open: %s\n", cert_file);
       // return EXIT_FAILURE;
    }

    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "unable to parse certificate in: %s\n", cert_file);
        fclose(fp);
      //  return EXIT_FAILURE;  
    }

    unsigned char* buf;
    buf = NULL;
    len = i2d_X509(cert, &buf);  // converting to unsigned char*

    std::string cartificate(buf, buf + len);
    fclose(fp);
    std::cout << cartificate << std::endl;

    

    tls_certificate server_certificate_msg;
    uint32_t len2 = cartificate.size() + 3;
    // send certificate
    uint32_t total_len = 3 + len2;
    server_certificate_msg.msg_type = CERTIFICATE;
    server_certificate_msg.length[0] = (total_len >> 16) & 0xFF;
    server_certificate_msg.length[1] = (total_len >> 8) & 0xFF;
    server_certificate_msg.length[2] = total_len & 0xFF;
     
    server_certificate_msg.cert_length[0] = (len2 >> 16) & 0xFF;
    server_certificate_msg.cert_length[1] = (len2 >> 8) & 0xFF;
    server_certificate_msg.cert_length[2] = len2 & 0xFF;


    // send server certificate
    tls_header server_certificate_header;
    server_certificate_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    server_certificate_header.version = htons(TLS_VERSION_TLSv1_2);
    server_certificate_header.length = htons(total_len + 4);

    std::string server_certificate_buffer;
    server_certificate_buffer.append((char*)&server_certificate_header, sizeof(tls_header));
    server_certificate_buffer.append((char*)&(server_certificate_msg), 7);
    
    // add 3 bytes of cartificate length
    uint8_t len3[3];
    len3[0] = (len >> 16) & 0xFF;
    len3[1] = (len >> 8) & 0xFF;
    len3[2] = len & 0xFF;
    server_certificate_buffer.append((char*)&len3, 3);

    server_certificate_buffer.append(cartificate);

   // sock->send(server_certificate_buffer, server_certificate_buffer.size(), 0, 0);
    server_hello_buffer.append(server_certificate_buffer);

    // send server hello done msg
    tls_header server_hello_done_header;
    server_hello_done_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    server_hello_done_header.version = htons(TLS_VERSION_TLSv1_2);
    server_hello_done_header.length = htons(4);

    uint8_t server_hell_done[4] = { 0x0e, 0x00, 0x00, 0x00 };

    std::string server_hello_done_buffer;
    server_hello_done_buffer.append((char*)&server_hello_done_header, sizeof(tls_header));
    server_hello_done_buffer.append((char*)&server_hell_done, 4);

    server_hello_buffer.append(server_hello_done_buffer);
    sock->send(server_hello_buffer, server_hello_buffer.size(), 0, 0);

    // receive client key exchange msg
    std::string recv_buffer2 = "";
    sock->recv(recv_buffer2, 1500, 1, 0);



    // get client key exchange msg
    tls_header* key_exchange_header = (tls_header*)recv_buffer2.c_str();

    if (ntohs(key_exchange_header->version) != TLS_VERSION_TLSv1_2) {
		std::cout << "version not match" << std::endl;
		return nullptr;
	}


    tls_key_exchanege_msg client_key_exchange;
    memcpy(&client_key_exchange, (char*)key_exchange_header + 5 , 4);
    client_key_exchange.premaster = std::string((char*)key_exchange_header + 9, ntohs(key_exchange_header->length) - 4);

    // decrypt the premaster secret
    // load the private key
    const char* key_file = "C:/Program Files/OpenSSL-Win64/server.key";
    FILE* key_fp = fopen(key_file, "r");
    if (!key_fp) {
		fprintf(stderr, "unable to open: %s\n", key_file);
		// return EXIT_FAILURE;
	}
    RSA* rsa_priv_key = PEM_read_RSAPrivateKey(key_fp, NULL, NULL, NULL);
    if (!rsa_priv_key) {
        // Handle error loading private key
        fprintf(stderr, "Error loading private key\n");
       // return EXIT_FAILURE;
    }
    
    uint8_t decrypted_premaster_secret[48];

  
    // Decrypt the premaster secret
    size_t a = client_key_exchange.premaster.size();
    uint8_t encrypted_premaster_secret[256] ;
    memcpy(encrypted_premaster_secret, client_key_exchange.premaster.data() + 2, 256);
    int decrypted_len = RSA_private_decrypt(256, encrypted_premaster_secret, decrypted_premaster_secret, rsa_priv_key, RSA_PKCS1_PADDING);
    if (decrypted_len == -1) {
        // Handle decryption error
        fprintf(stderr, "RSA_private_decrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        // Free resources and cleanup if necessary
        RSA_free(rsa_priv_key);
      //  return EXIT_FAILURE;
    }
    RSA_free(rsa_priv_key);


    // derive master secret
    unsigned char master_secret[48];
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), client_hello.random.random_bytes, client_hello.random.random_bytes + 32);
    seed.insert(seed.end(), server_hello_msg.random.random_bytes, server_hello_msg.random.random_bytes + 32);
    prf(seed, "master secret", std::vector<uint8_t>(decrypted_premaster_secret, decrypted_premaster_secret + 48), master_secret, 48);

    // master secret as a vector
    std::vector<uint8_t> master_secret_vec(master_secret, master_secret + 48);

    // key derive
    std::vector<uint8_t> seed1;
    seed1.insert(seed1.end(), server_hello_msg.random.random_bytes, server_hello_msg.random.random_bytes + 32);
    seed1.insert(seed1.end(), client_hello.random.random_bytes, client_hello.random.random_bytes + 32);
    uint8_t key_block[104];
    prf(seed1, "key expansion", master_secret_vec, key_block, 104);
    extract_key(key_block, 104);

    // get change cipher spec msg
    uint32_t key_exchange_len = client_key_exchange.length[0] << 16 | client_key_exchange.length[1] << 8 | client_key_exchange.length[2];
    tls_header* change_cipher_spec_header = (tls_header*)(recv_buffer2.c_str() + sizeof(tls_header) + key_exchange_len + 4);

    tls_header* client_finished_header = (tls_header*)((char*)change_cipher_spec_header + sizeof(tls_header) + 1) ;
    
    std::vector<uint8_t> encrypted_data((char *)client_finished_header + sizeof(tls_header), (char*)client_finished_header + sizeof(tls_header) + ntohs(client_finished_header->length));

    // as string
    std::string encrypted_data_str(encrypted_data.begin(), encrypted_data.end());

    std::string client_verify_data = decrypt(encrypted_data_str, true);

    // concatinating hanshake nassages
    std::vector<uint8_t> handshake_msg;

    handshake_msg.insert(handshake_msg.end(), start_of_client_hello, start_of_client_hello + htons(recv_header->length));

    handshake_msg.insert(handshake_msg.end(), server_hello_msg_raw.begin(), server_hello_msg_raw.end());

    handshake_msg.insert(handshake_msg.end(), server_certificate_buffer.begin() + sizeof(tls_header), server_certificate_buffer.end());

    handshake_msg.insert(handshake_msg.end(), server_hell_done, server_hell_done + 4);

    handshake_msg.insert(handshake_msg.end(), (char*)key_exchange_header + 5, (char*)key_exchange_header + 5 + ntohs(key_exchange_header->length));


    // verify the client verify data
    uint8_t hash_msg[32];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg);
    std::vector<uint8_t> seed2(hash_msg, hash_msg + 32);
    uint8_t verify_data[12];
    prf(seed2, "client finished", master_secret_vec, verify_data, 12);

    // create client change cipher spec msg
    tls_header client_change_cipher_spec_header;
    client_change_cipher_spec_header.type = TLS_CONNECTION_TYPE_CHANGE_CIPHER_SPEC;
    client_change_cipher_spec_header.version = htons(TLS_VERSION_TLSv1_2);
    client_change_cipher_spec_header.length = htons(1);

    uint8_t change_cipher_spec = 0x01;
    std::string change_cipher_spec_msg;
    change_cipher_spec_msg.append((char*)&client_change_cipher_spec_header, sizeof(client_change_cipher_spec_header));
    change_cipher_spec_msg.append((char*)&change_cipher_spec, 1);

    // derive server verif data for verification
    handshake_msg.insert(handshake_msg.end(), client_verify_data.begin(), client_verify_data.end());
    uint8_t hash_msg2[32];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg2);
    std::vector<uint8_t> seed23(hash_msg2, hash_msg2 + 32);
    uint8_t server_verify_data[12];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, 12);

    // create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);

    // compose message to encrypt
    std::vector<uint8_t> final_msg = { 0x14, 0x00 , 0x00 , 0x0c };
    final_msg.insert(final_msg.end(), server_verify_data, server_verify_data + 12);

    // encrypt final msg
    std::string final_msg_str(final_msg.begin(), final_msg.end());
    std::string encrypted_final_msg = encrypt(final_msg_str, true);

    encrypted_handshake_header.length = htons(encrypted_final_msg.size());

    std::string encrypted_handshake_msg;

    // add change cipher spec
    encrypted_handshake_msg.append(change_cipher_spec_msg);
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));
    encrypted_handshake_msg.append(encrypted_final_msg);

    sock->send(encrypted_handshake_msg, encrypted_handshake_msg.size(), 0, 0);





    return sock;
}


void tls_socket::connect(const struct sockaddr* name, int name_len) {
    
    // first establish tcp connection
    p_socket->connect(name, name_len);
    
    // send client hello
    tls_header header;
    header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    header.version = htons(TLS_VERSION_TLSv1_0);
        
    // init client hello msg
    TLSHello client_msg;    
    client_msg.msg_type = CLIENT_HELLO;
    client_msg.tls_version = htons(TLS_VERSION_TLSv1_2);
    
    // set random bytes
    RAND_bytes(client_msg.random.random_bytes, 32);

    client_msg.session_id = {};
    client_msg.cipher_suites = { 0x2f00, 0x3500 };
    client_msg.compression_methods = { NULL_COMPRESSION };
    client_msg.extensions = {};

  
    uint32_t msg_len = 43;
    client_msg.length[0] = (msg_len >> 16) & 0xFF;
    client_msg.length[1] = (msg_len >> 8) & 0xFF;
    client_msg.length[2] = msg_len & 0xFF;
    
  
    // create a buffer to store the client hello msg
    std::string buffer;
   
    std::string msg_to_send = client_msg.parse();
    uint16_t total_length = msg_to_send.size();
    header.length = htons(total_length);
    buffer.append((char*)&header, sizeof(tls_header));
    buffer.append(msg_to_send);


    // send client hello msg
    p_socket->send(buffer, buffer.size(), 0, 0);

    std::cout << "finish send client hello" << std::endl;

    // we need to change the state to wait for server hello
    std::string recv_buffer;

    //std::this_thread::sleep_for(std::chrono::milliseconds(4000));
   
    p_socket->recv(recv_buffer, 1500, 1, 0);

    // verify version
    tls_header* recv_header = (tls_header*)recv_buffer.c_str();
    if (ntohs(recv_header->version) != TLS_VERSION_TLSv1_2) {
		std::cout << "version not match" << std::endl;
		return;
	}

    // get the server hello msg
    char* start_of_server_hello = (char*)recv_buffer.c_str() + sizeof(tls_header);
    TLSHello server_hello(start_of_server_hello);

    std::cout << "finish receive server hello" << std::endl;
    // verify the server hello msg
    // TODO: implemtent the verification method


    // get server cartificate

    uint32_t ser_msg_len = (server_hello.length[0] << 16) + (server_hello.length[1] << 8) + server_hello.length[2] ;
    char* start_of_next_header = start_of_server_hello + ser_msg_len + 4;
    char* start_of_server_certificate = start_of_next_header + sizeof(tls_header);
  
    tls_certificate cartificate(start_of_server_certificate);
    
    std::cout << "finish receive server certificate" << std::endl;

    // verify the certificate
    msg_len = (cartificate.length[0] << 16) + (cartificate.length[1] << 8) + cartificate.length[2];
    start_of_next_header = start_of_server_certificate + msg_len + 4;
    char*  start_of_server_hello_done = start_of_next_header + sizeof(tls_header);

    std::cout << "finish receive server hello done" << std::endl;

    // verify the server hello done msg TODO: implement the verification method

    uint32_t raw_cartificate_len = (cartificate.cert_length[0] << 16) | (cartificate.cert_length[1] << 8) | cartificate.cert_length[2];
    
    extract_public_key(&cartificate.cert.data()[3], cartificate.cert.size() - 3);

    // generate a random premaster secret
    uint8_t premaster_secret[48];
    RAND_bytes(premaster_secret, 48);
    premaster_secret[0] = 0x03;
    premaster_secret[1] = 0x03; 


    // encrypt the premaster secret using the public key
    uint8_t encrypted_premaster_secret[256];
    int rt = RSA_public_encrypt(48, premaster_secret, encrypted_premaster_secret, p_rsa, RSA_PKCS1_PADDING);
    std::cout << "encrypted premaster secret" << std::endl;
    
    // create the client key exchange msg
    tls_header client_key_exchange_header;

    client_key_exchange_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    client_key_exchange_header.version = htons(TLS_VERSION_TLSv1_2);
    client_key_exchange_header.length = htons(256 + 6);

    tls_key_exchanege_msg key_exchange_msg;
    key_exchange_msg.msg_type = CLIENT_KEY_EXCHANGE;
    key_exchange_msg.length[0] = 0x00;
    key_exchange_msg.length[1] = 0x01;
    key_exchange_msg.length[2] = 0x02;

    key_exchange_msg.premaster = std::string((char*)encrypted_premaster_secret, 256);

    // create a buffer to store the client key exchange msg
    std::string key_exchange_buffer;
    std::string msg_to_send2 = key_exchange_msg.parse();
    key_exchange_buffer.append((char*)&client_key_exchange_header, sizeof(tls_header));
    key_exchange_buffer.append(msg_to_send2);

    // create client change cipher spec msg
    tls_header client_change_cipher_spec_header;
    client_change_cipher_spec_header.type = TLS_CONNECTION_TYPE_CHANGE_CIPHER_SPEC;
    client_change_cipher_spec_header.version = htons(TLS_VERSION_TLSv1_2);
    client_change_cipher_spec_header.length = htons(1);

    uint8_t change_cipher_spec = 0x01;
    std::string change_cipher_spec_msg;
    change_cipher_spec_msg.append((char*)&client_change_cipher_spec_header, sizeof(client_change_cipher_spec_header));
    change_cipher_spec_msg.append((char*)&change_cipher_spec, 1);

    // add to buffer
    key_exchange_buffer.append(change_cipher_spec_msg);  

    auto pre = std::vector<uint8_t>(premaster_secret, premaster_secret + 48);
    auto client_rand = std::vector<uint8_t>(client_msg.random.random_bytes, client_msg.random.random_bytes + 32);
    auto server_rand = std::vector<uint8_t>(server_hello.random.random_bytes, server_hello.random.random_bytes + 32);

    // derive master secret
    unsigned char master_secret[48];
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());
    prf(seed, "master secret", pre, master_secret, 48);

    // master secret as a vector
    std::vector<uint8_t> master_secret_vec(master_secret, master_secret + 48);

    // key derive
    std::vector<uint8_t> seed1;
    seed1.insert(seed1.end(), server_rand.begin(), server_rand.end());
    seed1.insert(seed1.end(), client_rand.begin(), client_rand.end());
    uint8_t key_block[104];
    prf(seed1, "key expansion", master_secret_vec, key_block, 104);
    extract_key(key_block, 104);
    
     // prepare hanshake massages
    std::vector<uint8_t> plaintext;
    auto client_hello  = client_msg.parse();
    auto client_hello_msg = std::vector<uint8_t>(client_hello.begin(), client_hello.end());
    plaintext.insert(plaintext.end(), client_hello_msg.begin(), client_hello_msg.end()); // add client hello
    auto server_hello_msg = std::vector<uint8_t>(start_of_server_hello, start_of_server_hello + ser_msg_len  - 1 + 5);
    plaintext.insert(plaintext.end(), server_hello_msg.begin(), server_hello_msg.end()); // add server hello
    auto server_certificate = std::vector<uint8_t>(start_of_server_certificate , start_of_server_certificate + raw_cartificate_len + 3 - 1 + 5 );
    plaintext.insert(plaintext.end(), server_certificate.begin(), server_certificate.end());  // add server cartificate
    auto server_hello_done = std::vector<uint8_t>(start_of_server_hello_done, start_of_server_hello_done + 4);
    plaintext.insert(plaintext.end(), server_hello_done.begin(), server_hello_done.end()) ;   // add server hello done 
    plaintext.insert(plaintext.end(), msg_to_send2.begin(), msg_to_send2.end()); // client key exchange


    // derive verify data
    uint8_t hash_msg[32];
    SHA256(plaintext.data(), plaintext.size(), hash_msg);
    std::vector<uint8_t> seed2 (hash_msg, hash_msg + 32) ;
    uint8_t verify_data[12];
    prf(seed2, "client finished", master_secret_vec, verify_data, 12);


    // compose message to encrypt
    std::vector<uint8_t> final_msg = { 0x14, 0x00 , 0x00 , 0x0c };
    final_msg.insert(final_msg.end(), verify_data, verify_data + 12);

    // encrypt final msg
    std::string final_msg_str(final_msg.begin(), final_msg.end());
    std::string encrypted_final_msg = encrypt(final_msg_str);

    // create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);
    encrypted_handshake_header.length = htons(64);

    std::string encrypted_handshake_msg;
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));

    // add to buffer
    encrypted_handshake_msg.insert(encrypted_handshake_msg.end(), encrypted_final_msg.begin(), encrypted_final_msg.end());
    key_exchange_buffer.append(encrypted_handshake_msg);


    // send client key exchange msg 
    p_socket->send(key_exchange_buffer, key_exchange_buffer.size(), 0, 0);



    std::cout << "finish send client key exchange" << std::endl;
    recv_buffer.clear();
    p_socket->recv(recv_buffer, 1500, 1, 0); // tls recive


    std::cout << "finish receive server change cipher spec" << std::endl;

    // verify the server change cipher spec msg
    tls_header* recv_header2 = (tls_header*)recv_buffer.c_str();
    if (ntohs(recv_header2->version) != TLS_VERSION_TLSv1_2) {
		std::cout << "version not match" << std::endl;
		return;
	}


    // get encrypted handshake msg
    char* start_of_encrypted_handshake = (char*)recv_buffer.c_str() + sizeof(tls_header) + 1;
    tls_header* encrypted_handshake_header1 = (tls_header*)start_of_encrypted_handshake;
    uint32_t encrypted_handshake_len = 64;
    char* start_of_encrypted_handshake_msg = start_of_encrypted_handshake + sizeof(tls_header);

    // Decrypt the message
    std::string decrypted = decrypt(std::string(start_of_encrypted_handshake_msg, start_of_encrypted_handshake_msg + encrypted_handshake_len));


    // derive server verif data for verification
    plaintext.insert(plaintext.end(), final_msg.begin(), final_msg.end());
    uint8_t hash_msg2[32];
    SHA256(plaintext.data(), plaintext.size(), hash_msg2);
    std::vector<uint8_t> seed23 (hash_msg2, hash_msg2 + 32);
    uint8_t server_verify_data[12];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, 12);

    std::cout << decrypted << std::endl;
}


void tls_socket::shutdown(int how) {
    // TODO: Implement shutdown method for TLS socket
    p_socket->shutdown(how);


}

// Function to add PKCS7 padding to the message
void add_pkcs7_padding(std::vector<uint8_t>& message, size_t block_size)
{
    size_t padding_length = (block_size - (message.size() % block_size)) - 1;
    uint8_t padding_value = static_cast<uint8_t>(padding_length);

    message.insert(message.end(), padding_length, padding_value);
    message.insert(message.end(), 1, padding_value);
}

void tls_socket::send(std::string uio, size_t uio_resid, size_t chunk, int flags) {

    std::string encrypted_msg = encrypt(uio);

    // create encrypted handshake msg
    tls_header header;
    header.type = TLS_CONNECTION_TYPE_APPLICATION_DATA;
    header.version = htons(TLS_VERSION_TLSv1_2);
    header.length = htons(encrypted_msg.size());


    char buff[5];
    memcpy(buff, &header, sizeof(tls_header));
    encrypted_msg.insert(encrypted_msg.begin(), buff, buff + sizeof(tls_header));



    p_socket->send(encrypted_msg, encrypted_msg.size(), 0, 0);
 
}

int tls_socket::recv(std::string& uio, size_t uio_resid, size_t chunk, int flags) {

    std::string recv_buffer;
    p_socket->recv(recv_buffer, uio_resid, chunk, flags);
    
    // get header
    tls_header* recv_header = (tls_header*)recv_buffer.c_str();

    // get start of the encrypted data
    char* start_of_encrypted_data = (char*)recv_buffer.c_str() + sizeof(tls_header);

    std::string encrtped_msg(start_of_encrypted_data, start_of_encrypted_data + ntohs(recv_header->length));

    uio = decrypt(encrtped_msg);

	
	return 0;

}

void tls_socket::extract_key(uint8_t* keyblock, size_t keyblock_len)
{
    // Extract keys and IVs from key_block
    unsigned char* ptr = keyblock;
    memcpy(client_write_MAC, ptr, 20);    ptr += 20;
    memcpy(server_write_MAC, ptr, 20);    ptr += 20;
    memcpy(client_write_key, ptr, 16);    ptr += 16;
    memcpy(server_write_key, ptr, 16);    ptr += 16;
    memcpy(client_write_IV, ptr, 16);     ptr += 16;
    memcpy(server_write_IV, ptr, 16);     ptr += 16;
}

void tls_socket::prf(std::vector<uint8_t>& seed, std::string label, std::vector<uint8_t>& secret, uint8_t* res, size_t res_len)
{

    std::vector<uint8_t> final_seed;
    final_seed.insert(final_seed.end(), label.begin(), label.end());
    final_seed.insert(final_seed.end(), seed.begin(), seed.end());

    EVP_PKEY_CTX* pctx;

    size_t outlen = res_len;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) return;
    if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) return;
    if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret.data(), secret.size()) <= 0) return;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, final_seed.data(), final_seed.size()) <= 0) return;
    if (EVP_PKEY_derive(pctx, res, &outlen) <= 0) return;
    EVP_PKEY_CTX_free(pctx);
}

std::string tls_socket::encrypt(std::string& msg, bool server )  {

    std::vector<uint8_t> text(msg.data(), msg.data() + msg.size());
    std::vector<uint8_t> to_mac;

    uint8_t first_byte = client_seq_num & 0xff;
    uint8_t type = first_byte == 0 ? 0x16 : 0x17;
    client_seq_num++;
    
    uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, first_byte };
    uint8_t rest[5] = { type, 0x03, 0x03 };  // Handshake type 0x16, version 0x0303 (TLS 1.2)

    // Correct length (high byte, low byte)
    uint16_t length = text.size();
    rest[3] = (length >> 8) & 0xff;
    rest[4] = length & 0xff;

    to_mac.insert(to_mac.end(), seq_bym, seq_bym + sizeof(seq_bym));
    to_mac.insert(to_mac.end(), rest, rest + sizeof(rest));
    to_mac.insert(to_mac.end(), text.begin(), text.end());


    // Compute HMAC-SHA1
    unsigned char mac[20];
    unsigned int mac_len;

    unsigned char* mac_key = server ? server_write_MAC : client_write_MAC;

    HMAC(EVP_sha1(), mac_key, 20, to_mac.data(), to_mac.size(), mac, &mac_len);

    text.insert(text.end(), mac, mac + 20);
    add_pkcs7_padding(text, 16);

    // Encrypt the padded message
    EVP_CIPHER_CTX* ctx3 = EVP_CIPHER_CTX_new();
    int s = EVP_CIPHER_CTX_reset(ctx3);
    if (!ctx3) return "";

    int lenn;
    int ciphertext_len_temp = 0;
    std::vector<uint8_t> ciphertext1(1000);  // Ensure the buffer is large enough
    unsigned char * key = server ? server_write_key : client_write_key;
    unsigned char* IV = server ? server_write_IV : client_write_IV;

    if (EVP_EncryptInit_ex(ctx3, EVP_aes_128_cbc(), NULL, key, IV) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    if (EVP_EncryptUpdate(ctx3, ciphertext1.data(), &lenn, text.data(), text.size()) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    ciphertext_len_temp = lenn;

    ciphertext1.resize(ciphertext_len_temp);

    ciphertext1.insert(ciphertext1.begin(), IV, IV + 16);

    std::string ss;
    ss.insert(ss.end(), ciphertext1.begin(), ciphertext1.end());
    EVP_CIPHER_CTX_free(ctx3);
    return ss;
}

std::string tls_socket::decrypt(std::string& msg, bool server )  {
   
    // get iv
    std::vector<uint8_t> iv = std::vector<uint8_t>(msg.data(), msg.data() + 16);

    // get encrypted data
    std::vector<uint8_t> encrypted_data = std::vector<uint8_t>(msg.data() + 16, msg.data() + msg.size());

    // Decrypt the message
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int lenn;
    int lenn2;
    std::vector<uint8_t> text(1000);

    unsigned char* key = server ? client_write_key : server_write_key ;

    int s1 = EVP_CIPHER_CTX_reset(ctx);
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv.data()) != 1) {
        ERR_print_errors_fp(stderr);
        return 0;


    }

    if (EVP_DecryptUpdate(ctx, text.data(), &lenn, encrypted_data.data(), encrypted_data.size()) != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    auto decryptedtext_len = lenn;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, text.data() + lenn, &lenn2)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    decryptedtext_len += lenn2;
    auto dec_len = decryptedtext_len - 21;
    std::vector<uint8_t> text1(text.data(), text.data() + dec_len);

    std::vector<uint8_t> to_mac;
    uint8_t first_byte = server_seq_num & 0xff;
    uint8_t type = first_byte == 0 ? 0x16 : 0x17;
    server_seq_num++;

    uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, first_byte };
    uint8_t rest[5] = { type, 0x03, 0x03 };  // Handshake type 0x16, version 0x0303 (TLS 1.2)

    // Correct length (high byte, low byte)
    uint16_t length = text1.size();
    rest[3] = (length >> 8) & 0xff;
    rest[4] = length & 0xff;

    to_mac.insert(to_mac.end(), seq_bym, seq_bym + sizeof(seq_bym));
    to_mac.insert(to_mac.end(), rest, rest + sizeof(rest));
    to_mac.insert(to_mac.end(), text1.begin(), text1.end());


    // Compute HMAC-SHA1
    unsigned char mac[20];
    unsigned int mac_len;

    unsigned char* key_mac = server ? client_write_MAC : server_write_MAC;

    HMAC(EVP_sha1(), key_mac, 20, to_mac.data(), to_mac.size(), mac, &mac_len);

    // validate the mac
    if (memcmp(mac, text.data() + dec_len, 20) != 0) 
    {
        std::cout << "mac not match" << std::endl;
        return "";
    }

    std::string decrypted(text1.data(), text1.data() + text1.size());

    EVP_CIPHER_CTX_free(ctx);

    return decrypted;
}


