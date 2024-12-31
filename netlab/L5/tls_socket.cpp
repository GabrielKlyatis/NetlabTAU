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

#include "tls_socket.h"

#pragma warning(disable : 4996)
#define MAX_MTU    5000

using namespace netlab;

// Function to add PKCS7 padding to the message
void add_pkcs7_padding(std::vector<uint8_t>& message, size_t block_size) {
    size_t padding_length = (block_size - (message.size() % block_size)) - 1;
    uint8_t padding_value = static_cast<uint8_t>(padding_length);

    message.insert(message.end(), padding_length, padding_value);
    message.insert(message.end(), 1, padding_value);
}

void secure_socket::prf(std::vector<uint8_t>& seed, std::string label, std::vector<uint8_t>& secret, uint8_t* res, size_t res_len) {

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

    // Choose keys
    unsigned char* mac_key = server ? server_write_MAC : client_write_MAC;
    unsigned char* key = server ? server_write_key : client_write_key;
    unsigned char* IV = server ? server_write_IV : client_write_IV;

    uint8_t first_byte = client_seq_num & 0xff;
    uint8_t type = first_byte == 0 ? TLS_CONTENT_TYPE_HANDSHAKE : TLS_CONTENT_TYPE_APPLICATION_DATA;
    client_seq_num++;

    uint8_t seq_bym[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, first_byte };
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
    std::vector<uint8_t> ciphertext(MAX_MTU);  // Ensure the buffer is large enough
   
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

    // Decide on keys
    unsigned char* key = server ? client_write_key : server_write_key;
    unsigned char* key_mac = server ? client_write_MAC : server_write_MAC;

    // Decrypt the message
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int lenn, lenn2;

    std::vector<uint8_t> text(MAX_MTU);

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
    uint8_t first_byte = server_seq_num & 0xff;
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
    std::string decrypted(text1.data(), text1.data() + text1.size());
  
    HMAC(EVP_sha1(), key_mac, MAC_KEY_SIZE, to_mac.data(), to_mac.size(), mac, &mac_len);

    // Validate the mac
    if (memcmp(mac, text.data() + dec_len, MAC_KEY_SIZE) != 0)
    {
        std::cout << "mac not match" << std::endl;
        return decrypted;
    }

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

void tls_socket::bind(const struct sockaddr* addr, int addr_len) {
    p_socket->bind(addr, addr_len);
}

void tls_socket::listen(int backlog) {  
    p_socket->listen(backlog);
}

std::vector<uint8_t> get_certificate() {

    // Create the certificate
    const char* cert_file = "OpenSSL-Win32/server.crt";

    FILE* fp = fopen(cert_file, "r");
    if (!fp) {
        fprintf(stderr, "unable to open: %s\n", cert_file);
        // return EXIT_FAILURE;
    }

    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "unable to parse certificate in: %s\n", cert_file);
        fclose(fp);
        // return EXIT_FAILURE;
    }

    uint32_t len = 70;
    unsigned char* buf;
    buf = NULL;
    len = i2d_X509(cert, &buf);  // Converting to unsigned char*

    std::vector<uint8_t> certificate(buf, buf + len);
    return certificate;
}

void rsa_decrypt(uint8_t decrypted_premaster_secret[MASTER_SECRET_SIZE], uint8_t encrypted[PRE_MASTER_SECRET_ENCRYPTED_SIZE]) {
    // Load the private key
    const char* key_file = "OpenSSL-Win32/server.key";
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


std::vector<uint8_t> tls_socket::derive_master_secret(std::vector<uint8_t> pre_master_vec, std::string client_rand ,std::string server_rand) {
    unsigned char master_secret[MASTER_SECRET_SIZE];
    std::vector<uint8_t> seed;

    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());

    prf(seed, "master secret", pre_master_vec, master_secret, MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec(master_secret, master_secret + MASTER_SECRET_SIZE); // Master secret as a vector

    return master_secret_vec;
}

void tls_socket::derive_keys(std::vector<uint8_t> master_sercret, std::string client_rand, std::string server_rand) {
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());
    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    uint8_t key_block[KEY_BLOCK_SIZE];
    prf(seed, "key expansion", master_sercret, key_block, KEY_BLOCK_SIZE);
    extract_key(key_block, KEY_BLOCK_SIZE);
}

L5_socket* tls_socket::accept(struct sockaddr* addr, int* addr_len) {
    L5_socket* sock = p_socket->accept(addr, addr_len);
    return sock;
}

void tls_socket::shutdown(int how) {
    p_socket->shutdown(how);
}

void tls_socket::extract_key(uint8_t* keyblock, size_t keyblock_len) {
    // Extract keys and IVs from key_block
    unsigned char* ptr = keyblock;
    memcpy(client_write_MAC, ptr, MAC_KEY_SIZE);    ptr += MAC_KEY_SIZE;
    memcpy(server_write_MAC, ptr, MAC_KEY_SIZE);    ptr += MAC_KEY_SIZE;
    memcpy(client_write_key, ptr, ENCRYPTION_KEY_SIZE);    ptr += ENCRYPTION_KEY_SIZE;
    memcpy(server_write_key, ptr, ENCRYPTION_KEY_SIZE);    ptr += ENCRYPTION_KEY_SIZE;
    memcpy(client_write_IV, ptr, IV_KEY_SIZE);     ptr += IV_KEY_SIZE;
    memcpy(server_write_IV, ptr, IV_KEY_SIZE);     ptr += IV_KEY_SIZE;
}