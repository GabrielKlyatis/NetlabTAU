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

#define MAX_MTU     1500


using namespace netlab;


// Function to add PKCS7 padding to the message
void add_pkcs7_padding(std::vector<uint8_t>& message, size_t block_size)
{
    size_t padding_length = (block_size - (message.size() % block_size)) - 1;
    uint8_t padding_value = static_cast<uint8_t>(padding_length);

    message.insert(message.end(), padding_length, padding_value);
    message.insert(message.end(), 1, padding_value);
}

void secure_socket::prf(std::vector<uint8_t>& seed, std::string label, std::vector<uint8_t>& secret, uint8_t* res, size_t res_len)
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


std::string secure_socket::encrypt(std::string& msg, bool server) {

    std::vector<uint8_t> text(msg.data(), msg.data() + msg.size());
    std::vector<uint8_t> to_mac;

    // choose keys
    unsigned char* mac_key = server ? server_write_MAC : client_write_MAC;
    unsigned char* key = server ? server_write_key : client_write_key;
    unsigned char* IV = server ? server_write_IV : client_write_IV;

    uint8_t first_byte = client_seq_num & 0xff;
    uint8_t type = first_byte == 0 ? TLS_CONTENT_TYPE_HANDSHAKE : TLS_CONTENT_TYPE_APPLICATION_DATA;
    client_seq_num++;

    uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, first_byte }; // can be optemize but not really importent now
    uint8_t rest[5] = { type, 0x03, 0x03 };  // Handshake type , version

    // Correct length (high byte, low byte)
    uint16_t length = text.size();
    rest[3] = (length >> 8) & 0xff;
    rest[4] = length & 0xff;

    to_mac.insert(to_mac.end(), seq_bym, seq_bym + sizeof(seq_bym));
    to_mac.insert(to_mac.end(), rest, rest + sizeof(rest));
    to_mac.insert(to_mac.end(), text.begin(), text.end());


    // Compute HMAC-SHA1
    unsigned char mac[MAC_KEY_SIZE];
    unsigned int mac_len;


    HMAC(EVP_sha1(), mac_key, MAC_KEY_SIZE, to_mac.data(), to_mac.size(), mac, &mac_len);

    text.insert(text.end(), mac, mac + MAC_KEY_SIZE);
    add_pkcs7_padding(text, ENCRYPTION_KEY_SIZE);

    // Encrypt the padded message
    EVP_CIPHER_CTX* ctx3 = EVP_CIPHER_CTX_new();
    int s = EVP_CIPHER_CTX_reset(ctx3);
    if (!ctx3) return "";

    int lenn;
    int ciphertext_len_temp = 0;
    std::vector<uint8_t> ciphertext(1000);  // Ensure the buffer is large enough
   

    if (EVP_EncryptInit_ex(ctx3, EVP_aes_128_cbc(), NULL, key, IV) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    if (EVP_EncryptUpdate(ctx3, ciphertext.data(), &lenn, text.data(), text.size()) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    ciphertext_len_temp = lenn;

    ciphertext.resize(ciphertext_len_temp);

    ciphertext.insert(ciphertext.begin(), IV, IV + IV_KEY_SIZE);

    std::string encrypted;
    encrypted.insert(encrypted.end(), ciphertext.begin(), ciphertext.end());
    EVP_CIPHER_CTX_free(ctx3);

    return encrypted;
}

std::string secure_socket::decrypt(std::string& msg, bool server) {

    std::vector<uint8_t> iv = std::vector<uint8_t>(msg.data(), msg.data() + IV_KEY_SIZE);
    std::vector<uint8_t> encrypted_data = std::vector<uint8_t>(msg.data() + IV_KEY_SIZE, msg.data() + msg.size());

    // decide keys
    unsigned char* key = server ? client_write_key : server_write_key;
    unsigned char* key_mac = server ? client_write_MAC : server_write_MAC;

    // Decrypt the message
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int lenn, lenn2;

    std::vector<uint8_t> text(1000);

  
    int s1 = EVP_CIPHER_CTX_reset(ctx);
    if (!ctx) return "";

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv.data()) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    if (EVP_DecryptUpdate(ctx, text.data(), &lenn, encrypted_data.data(), encrypted_data.size()) != 1) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    auto decryptedtext_len = lenn;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, text.data() + lenn, &lenn2)) {
        ERR_print_errors_fp(stderr);
        return "";
    }

    decryptedtext_len += lenn2;
    auto dec_len = decryptedtext_len - 21;
    std::vector<uint8_t> text1(text.data(), text.data() + dec_len);

    std::vector<uint8_t> to_mac;
    uint8_t first_byte = server_seq_num & 0xff; // TODO: bug
    uint8_t type = first_byte == 0 ? TLS_CONTENT_TYPE_HANDSHAKE : TLS_CONTENT_TYPE_APPLICATION_DATA;
    server_seq_num++;

    uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, first_byte };
    uint8_t rest[5] = { type, 0x03, 0x03 };  // Handshake type , version 

    // Correct length (high byte, low byte)
    uint16_t length = text1.size();
    rest[3] = (length >> 8) & 0xff;
    rest[4] = length & 0xff;

    to_mac.insert(to_mac.end(), seq_bym, seq_bym + sizeof(seq_bym));
    to_mac.insert(to_mac.end(), rest, rest + sizeof(rest));
    to_mac.insert(to_mac.end(), text1.begin(), text1.end());


    // Compute HMAC-SHA1
    unsigned char mac[MAC_KEY_SIZE];
    unsigned int mac_len;

  
    HMAC(EVP_sha1(), key_mac, MAC_KEY_SIZE, to_mac.data(), to_mac.size(), mac, &mac_len);

    // validate the mac
    if (memcmp(mac, text.data() + dec_len, MAC_KEY_SIZE) != 0)
    {
        std::cout << "mac not match" << std::endl;
        return "";
    }

    std::string decrypted(text1.data(), text1.data() + text1.size());

    EVP_CIPHER_CTX_free(ctx);

    return decrypted;
}




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



tls_socket::tls_socket(inet_os& inet, bool server) : secure_socket(inet), server(server) {


}

tls_socket::~tls_socket() {


}


void tls_socket::bind(const struct sockaddr* addr, int addr_len) {
    p_socket->bind(addr, addr_len);
}

void tls_socket::listen(int backlog) {  
    p_socket->listen(backlog);
   
}


std::vector<uint8_t> get_certificate()
{
    // create certificate
    const char* cert_file = "C:/Projects/OpenSSL-Win64/server.crt";

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
    uint32_t len = 70;
    unsigned char* buf;
    buf = NULL;
    len = i2d_X509(cert, &buf);  // converting to unsigned char*

    std::vector<uint8_t> certificate(buf, buf + len);
    return certificate;
}

void rsa_decrypt(uint8_t decrypted_premaster_secret[MASTER_SECRET_SIZE], uint8_t encrypted[PRE_MASTER_SECRET_ENCRYPTED_SIZE])
{
    // load the private key
    const char* key_file = "C:/Projects/OpenSSL-Win64/server.key";
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

    int decrypted_len = RSA_private_decrypt(256, encrypted, decrypted_premaster_secret, rsa_priv_key, RSA_PKCS1_PADDING);

    if (decrypted_len == -1) {
        // Handle decryption error
        fprintf(stderr, "RSA_private_decrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        // Free resources and cleanup if necessary
        RSA_free(rsa_priv_key);
        //  return EXIT_FAILURE;
    }
    RSA_free(rsa_priv_key);
}


std::vector<uint8_t> tls_socket::derrive_master_secret(std::vector<uint8_t> pre_master_vec, std::string client_rand ,std::string server_rand)
{
    unsigned char master_secret[MASTER_SECRET_SIZE];
    std::vector<uint8_t> seed;

    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());

    prf(seed, "master secret", pre_master_vec, master_secret, MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec(master_secret, master_secret + MASTER_SECRET_SIZE); // master secret as a vector

    return master_secret_vec;
}

void tls_socket::derrive_keys(std::vector<uint8_t> master_sercret, std::string client_rand, std::string server_rand)
{
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());
    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    uint8_t key_block[KEY_BLOCK_SIZE];
    prf(seed, "key expansion", master_sercret, key_block, KEY_BLOCK_SIZE);
    extract_key(key_block, KEY_BLOCK_SIZE);
}


void tls_socket::handshake()
{
    // Handle handshake
    std::string recv_buffer;
    //recv_buffer.reserve(MAX_MTU);
    int byte_recived = p_socket->recv(recv_buffer, MAX_MTU, 1, 0);

    // Get Client Hello msg
    HandshakeType msg_type = CLIENT_HELLO;
    TLSHandshakeProtocol client_hello;
    client_hello.handshake.configureHandshakeBody(msg_type);
    client_hello.updateHandshakeProtocol(msg_type);
    client_hello.deserialize_handshake_protocol_data(recv_buffer, msg_type);

    // Server Hello
    TLSHandshakeProtocol server_hello;
    msg_type = SERVER_HELLO;
    server_hello.handshake.configureHandshakeBody(msg_type);
    server_hello.updateHandshakeProtocol(msg_type);
    std::string server_hello_msg = server_hello.serialize_handshake_protocol_data(msg_type);
    std::string serialized_string(server_hello_msg);

    // Certificate
    msg_type = CERTIFICATE;
    auto certificate = get_certificate();
    TLSHandshakeProtocol server_certificate;
    server_certificate.handshake.configureHandshakeBody(msg_type);
    server_certificate.handshake.body.certificate->addCertificate(certificate);
    server_certificate.updateHandshakeProtocol(msg_type);
    std::string certificate_msg = server_certificate.serialize_handshake_protocol_data(msg_type);
    serialized_string.append(certificate_msg);

    // Server hello done
    TLSHandshakeProtocol server_hello_done;
    msg_type = SERVER_HELLO_DONE;
    server_hello_done.handshake.configureHandshakeBody(msg_type);
    server_hello_done.updateHandshakeProtocol(msg_type);
    std::string server_done = server_hello_done.serialize_handshake_protocol_data(msg_type);
    serialized_string.append(server_done);

    p_socket->send(serialized_string, serialized_string.size(), 0, 0);

    // Receive client key exchange msg
    std::string recv_buffer2 = "";
    p_socket->recv(recv_buffer2, MAX_MTU, 1, 0);

    // Reciving client key exchange, change cipher , client finished

    // Client key exchange
    TLSHandshakeProtocol key_exchange;
    msg_type = CLIENT_KEY_EXCHANGE;
    key_exchange.handshake.configureHandshakeBody(msg_type);
    key_exchange.deserialize_handshake_protocol_data(recv_buffer2,msg_type);

  
    // Decrypt the premaster secret
    uint8_t decrypted_premaster_secret[MASTER_SECRET_SIZE];
    rsa_decrypt(decrypted_premaster_secret, key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.data());
    
    // Derive master secret
    std::string client_rand = client_hello.handshake.body.clientHello->random.get_random();
    std::string server_rand = server_hello.handshake.body.clientHello->random.get_random();
    std::vector<uint8_t> pre_master_vec(decrypted_premaster_secret, decrypted_premaster_secret + MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec = derrive_master_secret(pre_master_vec, client_rand, server_rand);
    
    // Key deriviation
    derrive_keys(master_secret_vec, client_rand, server_rand);
    

    // Change cipher message
    ChangeCipherSpec changeCipherSpec;
    std::string cipher(recv_buffer2.begin() + key_exchange.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH, recv_buffer2.end());
    changeCipherSpec.deserialize_change_cipher_spec_data(cipher);


    // Finish message
    tls_header* client_finished_header = (tls_header*)(recv_buffer2.data() + key_exchange.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH + 6);
    std::vector<uint8_t> encrypted_data((char*)client_finished_header + sizeof(tls_header), (char*)client_finished_header + sizeof(tls_header) + ntohs(client_finished_header->length));

    // As string
    std::string encrypted_data_str(encrypted_data.begin(), encrypted_data.end());
    std::string client_verify_data = decrypt(encrypted_data_str, true);


    // Concatinating hanshake messages
    std::vector<uint8_t> handshake_msg;

    std::string client_hello_msg = client_hello.serialize_handshake_protocol_data(CLIENT_HELLO);
    handshake_msg.insert(handshake_msg.end(), recv_buffer.begin() + RECORD_LAYER_DEFAULT_LENGTH, recv_buffer.begin() + RECORD_LAYER_DEFAULT_LENGTH + client_hello.TLS_record_layer.length ); // client hello
    handshake_msg.insert(handshake_msg.end(), server_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_msg.end());
    handshake_msg.insert(handshake_msg.end(), certificate_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, certificate_msg.end());
    handshake_msg.insert(handshake_msg.end(), server_done.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_done.end());

    std::string client_ket_exchange = key_exchange.serialize_handshake_protocol_data(CLIENT_KEY_EXCHANGE);
    handshake_msg.insert(handshake_msg.end(), client_ket_exchange.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_ket_exchange.end());


    // verify the client verify data
    uint8_t hash_msg[SHA256_HASH_LEN];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg);
    std::vector<uint8_t> seed2(hash_msg, hash_msg + SHA256_HASH_LEN);
    uint8_t verify_data[VERIFY_DATA_LEN];
    prf(seed2, "client finished", master_secret_vec, verify_data, VERIFY_DATA_LEN);

    //change cipher massage
    ChangeCipherSpec changeCipherSpec2;
    changeCipherSpec2.setChangeCipherSpec();


    // derive server verif data for verification
    handshake_msg.insert(handshake_msg.end(), client_verify_data.begin(), client_verify_data.end());
    uint8_t hash_msg2[SHA256_HASH_LEN];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg2);
    std::vector<uint8_t> seed23(hash_msg2, hash_msg2 + SHA256_HASH_LEN);
    uint8_t server_verify_data[VERIFY_DATA_LEN];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, VERIFY_DATA_LEN);

    // create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONTENT_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);

    // compose message to encrypt
    std::vector<uint8_t> final_msg = { FINISHED, 0x00 , 0x00 , VERIFY_DATA_LEN };
    final_msg.insert(final_msg.end(), server_verify_data, server_verify_data + VERIFY_DATA_LEN);

    // encrypt final msg
    std::string final_msg_str(final_msg.begin(), final_msg.end());
    std::string encrypted_final_msg = encrypt(final_msg_str, true);

    encrypted_handshake_header.length = htons(encrypted_final_msg.size());

    std::string encrypted_handshake_msg;

    // add change cipher spec
    encrypted_handshake_msg.append(changeCipherSpec2.serialize_change_cipher_spec_data());
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


    // recive server hello, certificate, server hello done
    std::string recv_buffer;
    p_socket->recv(recv_buffer, MAX_MTU, 1, 0);

    msg_type = SERVER_HELLO;
    TLSHandshakeProtocol server_hello;
    server_hello.handshake.configureHandshakeBody(msg_type);
    server_hello.deserialize_handshake_protocol_data(recv_buffer, msg_type);


    msg_type = CERTIFICATE;
    TLSHandshakeProtocol recive_cartificate;
    recive_cartificate.handshake.configureHandshakeBody(msg_type);
    std::string frr (recv_buffer.begin() + server_hello.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH, recv_buffer.end());
    recive_cartificate.deserialize_handshake_protocol_data(frr, msg_type);
    extract_public_key(recive_cartificate.handshake.body.certificate->certificate_list[0].data(), recive_cartificate.handshake.body.certificate->certificate_list[0].size());


    msg_type = SERVER_HELLO_DONE;
    TLSHandshakeProtocol serv_hello_done;
    serv_hello_done.handshake.configureHandshakeBody(msg_type);
    std::string frr2(frr.begin() + recive_cartificate.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH, frr.end());
    serv_hello_done.deserialize_handshake_protocol_data(frr2, msg_type);

    // create the client key exchange , change cipher spce, client finish
    msg_type = CLIENT_KEY_EXCHANGE;
    TLSHandshakeProtocol client_key_exchange;
    client_key_exchange.handshake.configureHandshakeBody(msg_type);
    client_key_exchange.handshake.body.clientKeyExchange->key_exchange_algorithm = KEY_EXCHANGE_ALGORITHM_RSA;
    client_key_exchange.handshake.body.clientKeyExchange->createClientKeyExchange();
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>();

    // TODO: check why can use .pre_master_secret
    unsigned char pre[MASTER_SECRET_SIZE];
    unsigned char encrypt_pre[PRE_MASTER_SECRET_ENCRYPTED_SIZE];

    memcpy(pre, &client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret, sizeof(PreMasterSecret));
    RSA_public_encrypt(48, pre, encrypt_pre, p_rsa, RSA_PKCS1_PADDING);
    std::copy(std::begin(encrypt_pre), std::end(encrypt_pre), client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.begin());
 
    client_key_exchange.updateHandshakeProtocol(msg_type);
    std::string client_key_msg = client_key_exchange.serialize_handshake_protocol_data(msg_type);


    //change cipher massage
    ChangeCipherSpec changeCipherSpec;
    changeCipherSpec.setChangeCipherSpec();


    // derive master secret
    std::string client_rand = client_hello.handshake.body.clientHello->random.get_random();
    std::string server_rand = server_hello.handshake.body.clientHello->random.get_random();
    std::vector<uint8_t> pre_master_vec(pre, pre + MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec = derrive_master_secret(pre_master_vec, client_rand, server_rand);


    // key derive
    derrive_keys(master_secret_vec, client_rand, server_rand);

    
    // prepare hanshake massages
    std::vector<uint8_t> plaintext;
    std::string client_hello_body(client_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_hello_msg.end());
    plaintext.insert(plaintext.end(), client_hello_body.begin(), client_hello_body.end()); // add client hello
    std::string server_hello_msg = server_hello.serialize_handshake_protocol_data(SERVER_HELLO);
    plaintext.insert(plaintext.end(), server_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_msg.end()); // add server hello
    std::string server_certificate = recive_cartificate.serialize_handshake_protocol_data(CERTIFICATE);
    plaintext.insert(plaintext.end(), server_certificate.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_certificate.end());  // add server certificate
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
    encrypted_handshake_header.type = TLS_CONTENT_TYPE_HANDSHAKE;
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
    p_socket->recv(recv_buffer, MAX_MTU, 1, 0); // tls recive

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
    uint8_t hash_msg2[SHA256_HASH_LEN];
    SHA256(plaintext.data(), plaintext.size(), hash_msg2);
    std::vector<uint8_t> seed23 (hash_msg2, hash_msg2 + SHA256_HASH_LEN);
    uint8_t server_verify_data[VERIFY_DATA_LEN];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, VERIFY_DATA_LEN);


    return ;
}


void tls_socket::shutdown(int how) {
    p_socket->shutdown(how);
}



void tls_socket::send(std::string uio, size_t uio_resid, size_t chunk, int flags) {

    std::string encrypted_msg = encrypt(uio, server);

    // create encrypted handshake msg
    tls_header header;
    header.type = TLS_CONTENT_TYPE_APPLICATION_DATA;
    header.version = htons(TLS_VERSION_TLSv1_2);
    header.length = htons(encrypted_msg.size());


    char buff[RECORD_LAYER_DEFAULT_LENGTH];
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
    memcpy(client_write_MAC, ptr, MAC_KEY_SIZE);    ptr += MAC_KEY_SIZE;
    memcpy(server_write_MAC, ptr, MAC_KEY_SIZE);    ptr += MAC_KEY_SIZE;
    memcpy(client_write_key, ptr, ENCRYPTION_KEY_SIZE);    ptr += ENCRYPTION_KEY_SIZE;
    memcpy(server_write_key, ptr, ENCRYPTION_KEY_SIZE);    ptr += ENCRYPTION_KEY_SIZE;
    memcpy(client_write_IV, ptr, IV_KEY_SIZE);     ptr += IV_KEY_SIZE;
    memcpy(server_write_IV, ptr, IV_KEY_SIZE);     ptr += IV_KEY_SIZE;
}

