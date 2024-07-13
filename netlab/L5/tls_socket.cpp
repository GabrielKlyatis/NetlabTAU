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
#include "tls_protocol_layer.hpp"


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

    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free(bio);

    return 0;

}



tls_socket::tls_socket(inet_os& inet, bool server) : secure_socket(inet), client_seq_num(0), server_seq_num(0), server(server) {
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


void tls_socket::handshake()
{
    // handle handshake
    std::string recv_buffer;
    recv_buffer.reserve(1500);
    int byte_recived = p_socket->recv(recv_buffer, 1500, 1, 0);

    // get client hello msg
    HandshakeType msg_type = CLIENT_HELLO;
    TLSHandshakeProtocol client_hello;
    client_hello.handshake.configureHandshakeBody(msg_type);
    client_hello.updateHandshakeProtocol(msg_type);
    client_hello.deserialize_handshake_protocol_data(recv_buffer, msg_type);

    tls_header* recv_header = (tls_header*)recv_buffer.c_str();
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

    server_hello_msg.cipher_suites = { 0x2f00 };

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
    p_socket->send(server_hello_buffer, server_hello_buffer.size(), 0, 0);

    // receive client key exchange msg
    std::string recv_buffer2 = "";
    p_socket->recv(recv_buffer2, 1500, 1, 0);



    // get client key exchange msg
    tls_header* key_exchange_header = (tls_header*)recv_buffer2.c_str();

    if (ntohs(key_exchange_header->version) != TLS_VERSION_TLSv1_2) {
        std::cout << "version not match" << std::endl;
        return ;
    }


    tls_key_exchanege_msg client_key_exchange;
    memcpy(&client_key_exchange, (char*)key_exchange_header + 5, 4);
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
    uint8_t encrypted_premaster_secret[256];
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

    tls_header* client_finished_header = (tls_header*)((char*)change_cipher_spec_header + sizeof(tls_header) + 1);

    std::vector<uint8_t> encrypted_data((char*)client_finished_header + sizeof(tls_header), (char*)client_finished_header + sizeof(tls_header) + ntohs(client_finished_header->length));

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

    p_socket->send(encrypted_handshake_msg, encrypted_handshake_msg.size(), 0, 0);

}
L5_socket* tls_socket::accept(struct sockaddr* addr, int* addr_len) {


    L5_socket* sock = p_socket->accept(addr, addr_len);


  

    return sock;
}


void tls_socket::connect(const struct sockaddr* name, int name_len) {
    
    // first establish tcp connection
    p_socket->connect(name, name_len);

    // prepare client hello
    HandshakeType msg_type = CLIENT_HELLO;
    TLSHandshakeProtocol client_hello;
    client_hello.handshake.configureHandshakeBody(msg_type);
    client_hello.updateHandshakeProtocol(msg_type);

    // send client hello
    std::string client_hello_msg = client_hello.serialize_handshake_protocol_data(msg_type);
    p_socket->send(client_hello_msg, client_hello_msg.size(), 0, 0);


    // recive server hello, cartificate, server hello done
    std::string recv_buffer;
    p_socket->recv(recv_buffer, 1500, 1, 0);


    msg_type = SERVER_HELLO;
    TLSHandshakeProtocol server_hello;
    server_hello.handshake.configureHandshakeBody(msg_type);
    server_hello.deserialize_handshake_protocol_data(recv_buffer, msg_type);


    msg_type = CERTIFICATE;
    TLSHandshakeProtocol recive_cartificate;
    recive_cartificate.handshake.configureHandshakeBody(msg_type);
    std::string frr (recv_buffer.begin() +0x51 + 5, recv_buffer.end());
    recive_cartificate.deserialize_handshake_protocol_data(frr, msg_type);
    extract_public_key(recive_cartificate.handshake.body.certificate.certificate_list[0].data(), recive_cartificate.handshake.body.certificate.certificate_list[0].size());


    msg_type = SERVER_HELLO_DONE;
    TLSHandshakeProtocol serv_hello_done;
    serv_hello_done.handshake.configureHandshakeBody(msg_type);
    std::string frr2(frr.begin() + recive_cartificate.TLS_record_layer.length + 5, frr.end());
    serv_hello_done.deserialize_handshake_protocol_data(frr2, msg_type);


  

    // create the client key exchange , change cipher spce, client finish
    msg_type = CLIENT_KEY_EXCHANGE;
    TLSHandshakeProtocol client_key_exchange;
    client_key_exchange.handshake.configureHandshakeBody(msg_type);
    client_key_exchange.handshake.body.clientKeyExchange.key_exchange_algorithm = KEY_EXCHANGE_ALGORITHM_RSA;
    client_key_exchange.handshake.body.clientKeyExchange.createClientKeyExchange();
    client_key_exchange.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>();

    // TODO: check why can use .pre_master_secret
    unsigned char pre[48];
    unsigned char encrypt_pre[256];

    memcpy(pre, &client_key_exchange.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.pre_master_secret, sizeof(PreMasterSecret));
    RSA_public_encrypt(48, pre, encrypt_pre, p_rsa, RSA_PKCS1_PADDING);
    std::copy(std::begin(encrypt_pre), std::end(encrypt_pre), client_key_exchange.handshake.body.clientKeyExchange.client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.begin());
 
    client_key_exchange.updateHandshakeProtocol(msg_type);
    std::string client_key_msg = client_key_exchange.serialize_handshake_protocol_data(msg_type);


    //change cipher massage
    ChangeCipherSpec changeCipherSpec;
    changeCipherSpec.setChangeCipherSpec();


    // derive master secret
    unsigned char master_secret[MASTER_SECRET_SIZE];
    std::vector<uint8_t> seed;
    std::string client_rand = client_hello.handshake.body.clientHello.random.get_random();
    std::string server_rand = server_hello.handshake.body.clientHello.random.get_random();
    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());
    std::vector<uint8_t> pre_master_vec(pre, pre + MASTER_SECRET_SIZE);
    prf(seed, "master secret", pre_master_vec, master_secret, MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec(master_secret, master_secret + MASTER_SECRET_SIZE); // master secret as a vector


    // key derive
    std::vector<uint8_t> seed1;
    seed1.insert(seed1.end(), server_rand.begin(), server_rand.end());
    seed1.insert(seed1.end(), client_rand.begin(), client_rand.end());
    uint8_t key_block[KEY_BLOCK_SIZE];
    prf(seed1, "key expansion", master_secret_vec, key_block, KEY_BLOCK_SIZE);
    extract_key(key_block, KEY_BLOCK_SIZE);
    
    // prepare hanshake massages
    std::vector<uint8_t> plaintext;
    std::string client_hello_body(client_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_hello_msg.end());
    plaintext.insert(plaintext.end(), client_hello_body.begin(), client_hello_body.end()); // add client hello
    std::string server_hello_msg = server_hello.serialize_handshake_protocol_data(SERVER_HELLO);
    plaintext.insert(plaintext.end(), server_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_msg.end()); // add server hello
    std::string server_certificate = recive_cartificate.serialize_handshake_protocol_data(CERTIFICATE);
    plaintext.insert(plaintext.end(), server_certificate.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_certificate.end());  // add server cartificate
    std::string server_hello_done_msg = serv_hello_done.serialize_handshake_protocol_data(SERVER_HELLO_DONE);
    plaintext.insert(plaintext.end(), server_hello_done_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_done_msg.end()) ;   // add server hello done 
    plaintext.insert(plaintext.end(), client_key_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_key_msg.end()); // client key exchange


    // derive verify data
    uint8_t hash_msg[SHA256_HASH_LEN];
    SHA256(plaintext.data(), plaintext.size(), hash_msg);
    std::vector<uint8_t> seed2 (hash_msg, hash_msg + SHA256_HASH_LEN) ;
    uint8_t verify_data[VERIFY_DATA_LEN];
    prf(seed2, "client finished", master_secret_vec, verify_data, VERIFY_DATA_LEN);


    // compose message to encrypt
    std::vector<uint8_t> final_msg = { FINISHED, 0x00 , 0x00 , VERIFY_DATA_LEN };
    final_msg.insert(final_msg.end(), verify_data, verify_data + VERIFY_DATA_LEN);

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

    std::string key_exchange_buffer;
    key_exchange_buffer.append(client_key_msg);
    key_exchange_buffer.append(changeCipherSpec.serialize_change_cipher_spec_data());
    key_exchange_buffer.append(encrypted_handshake_msg);


    // send client key exchange msg 
    p_socket->send(key_exchange_buffer, key_exchange_buffer.size(), 0, 0);

    recv_buffer.clear();
    p_socket->recv(recv_buffer, 1500, 1, 0); // tls recive

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


    return ;
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

    std::string encrypted_msg = encrypt(uio, server);

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

    uio = decrypt(encrtped_msg, server);

	
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


