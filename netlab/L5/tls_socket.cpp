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
#include <openssl/evp.h>
#include <random>
extern "C" {
#include <openssl/applink.c>
}

#pragma warning(disable : 4996)

using namespace netlab;


// Helper function to perform HMAC-SHA384
std::vector<uint8_t> hmac_sha384(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int result_len = 0;

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha384(), nullptr);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, result.data(), &result_len);
    HMAC_CTX_free(ctx);

    result.resize(result_len);
    return result;
}

// PRF function for TLS 1.2 using HMAC-SHA384
std::vector<uint8_t> tls_prf(const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& seed, size_t output_length) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> a;
    std::vector<uint8_t> data;

    // A(0) = seed
    data.insert(data.end(), label.begin(), label.end());
    data.insert(data.end(), seed.begin(), seed.end());

    // A(1) = HMAC(secret, A(0))
    a = hmac_sha384(secret, data);

    while (result.size() < output_length) {
        // HMAC(secret, A(i) + seed)
        std::vector<uint8_t> hmac_data = a;
        hmac_data.insert(hmac_data.end(), data.begin(), data.end());
        std::vector<uint8_t> hmac_result = hmac_sha384(secret, hmac_data);

        result.insert(result.end(), hmac_result.begin(), hmac_result.end());

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha384(secret, a);
    }

    result.resize(output_length);
    return result;
}

// Function to derive the master secret
std::vector<uint8_t> tls_socket::extract_master_secret(const std::vector<uint8_t>& preMasterSecret, const std::vector<uint8_t>& clientRandom, const std::vector<uint8_t>& serverRandom) {
    std::string label = "master secret";
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
    seed.insert(seed.end(), serverRandom.begin(), serverRandom.end());

    size_t master_secret_length = 48; // Master secret is 48 bytes
    return tls_prf(preMasterSecret, label, seed, master_secret_length);
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

    // Print modulus and exponent
    std::cout << "Modulus: " << modulus_hex << std::endl;
    std::cout << "Exponent: " << exponent_hex << std::endl;

    


    EVP_PKEY_free(pubkey);
    X509_free(cert);
    BIO_free(bio);
    //OPENSSL_free(modulus_hex);
    //OPENSSL_free(exponent_hex);

    return 0;

}


void generateRandomData(uint8_t* data, int size) {
    // Create a random number generator engine
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 255); // Use uint16_t

    // Fill the array with random bytes
    for (int i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen)); // Cast to uint8_t
    }
}



tls_socket::tls_socket(inet_os& inet) : secure_socket(inet) {
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
        if (name) {
            // std::cout << name << std::hex <<  "\t value:    " << value << std::endl;
        }
        counter++;
    }
    //std::cout << std::dec << "Total number of supported cipher suites: " << counter << std::endl;
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
    


    return nullptr;
}



// Function to derive keys using HKDF
std::vector<uint8_t> hkdf_expand(
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length)
{
    std::vector<uint8_t> output(length);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX");

    if (EVP_PKEY_derive_init(pctx) <= 0) throw std::runtime_error("EVP_PKEY_derive_init failed");

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) throw std::runtime_error("EVP_PKEY_CTX_hkdf_mode failed");

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384()) <= 0) throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), secret.size()) <= 0) throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");

    std::vector<uint8_t> info(label.begin(), label.end());
    info.insert(info.end(), context.begin(), context.end());
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");

    size_t outlen = length;
    if (EVP_PKEY_derive(pctx, output.data(), &outlen) <= 0) throw std::runtime_error("EVP_PKEY_derive failed");

    EVP_PKEY_CTX_free(pctx);
    return output;
}

// Function to derive all necessary keys
void derive_session_keys(
    const std::vector<uint8_t>& master_secret,
    const std::vector<uint8_t>& client_random,
    const std::vector<uint8_t>& server_random,
    std::vector<uint8_t>& client_write_key,
    std::vector<uint8_t>& server_write_key,
    std::vector<uint8_t>& client_write_iv,
    std::vector<uint8_t>& server_write_iv)
{
    std::vector<uint8_t> key_block;
    std::vector<uint8_t> seed(client_random.size() + server_random.size());
    std::copy(client_random.begin(), client_random.end(), seed.begin());
    std::copy(server_random.begin(), server_random.end(), seed.begin() + client_random.size());

    // Derive the key block (AES 256 keys and IVs)
    key_block = hkdf_expand(master_secret, "key expansion", seed, 2 * 32 + 2 * 12); // AES-256 keys (32 bytes each) + IVs (12 bytes each)

    // Extract keys and IVs
    auto it = key_block.begin();
    client_write_key.assign(it, it + 32); it += 32;
    server_write_key.assign(it, it + 32); it += 32;
    client_write_iv.assign(it, it + 12); it += 12;
    server_write_iv.assign(it, it + 12);
}

// Encrypt data using AES-256-GCM
std::vector<uint8_t> aes_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl failed");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    int len;
    std::vector<uint8_t> ciphertext(plaintext.size());
    int ciphertext_len;

    //if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
    //    throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate (plaintext) failed");
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += len;

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");

    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::vector<uint8_t> construct_verify_data(const std::vector<uint8_t>& masterSecret, const std::vector<uint8_t>& hashedHandshakeMessages) {
    std::string label = "client finished"; // or "server finished" depending on the context
    std::vector<uint8_t> verifyData;

    // Use the TLS PRF to derive the verify data
    verifyData = tls_prf(masterSecret, label, hashedHandshakeMessages, 12); // 12 bytes for TLS 1.2

    return verifyData;
}



std::vector<uint8_t> encryptMessage(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Initialize encryption context
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption context");
    }

    // Set the key and IV
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key and IV");
    }

    // Encrypt the message
    int len;
    std::vector<uint8_t> ciphertext(plaintext.size() + 16); // Reserve space for ciphertext + tag
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt message");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertext_len += len;

    // Get the tag
    std::vector<uint8_t> tag(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize ciphertext to the actual length
    ciphertext.resize(ciphertext_len);

    // Append tag to ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    return ciphertext;
}


void tls_socket::connect(const struct sockaddr* name, int name_len) {
    
    // first establish tcp connection
    p_socket->connect(name, name_len);


    std::cout << "finish ttcp hanshke" << std::endl;

    // send client hello
    tls_header header;
    header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    header.version = htons(TLS_VERSION_TLSv1_0);
        
    // init client hello msg
    TLSHello client_msg;    
    client_msg.msg_type = CLIENT_HELLO;

    client_msg.tls_version = htons(TLS_VERSION_TLSv1_2);
    
    // set random bytes
    generateRandomData(client_msg.random.random_bytes, 32);

    client_msg.session_id = {};
   
    client_msg.cipher_suites = get_cipher_suites();

    
    client_msg.compression_methods = { NULL_COMPRESSION };

    client_msg.extensions = {};

    // set header length
    
    
    uint32_t msg_len = sizeof(TLSHello) - 3;
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

    std::cout << "sizeof header" << sizeof(tls_header) << std::endl;
    std::cout << "sizeof client msg" << msg_to_send.size() << std::endl;

    p_socket->send(buffer, buffer.size(), 0, 0);

    std::cout << "finish send client hello" << std::endl;

    // we need to change the state to wait for server hello
    std::string recv_buffer;
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
    // TODO: implement the verification method

    msg_len = (cartificate.length[0] << 16) + (cartificate.length[1] << 8) + cartificate.length[2];
    start_of_next_header = start_of_server_certificate + msg_len + 4;
    char*  start_of_server_hello_done = start_of_next_header + sizeof(tls_header);

    std::cout << "finish receive server hello done" << std::endl;

    // verify the server hello done msg TODO: implement the verification method

    // send client key exchange
    auto a = server_hello.cipher_suites[0];
    auto b = server_hello.compression_methods[0];
    auto c = server_hello.session_id[0];

  //  tls_header client_key_exchange_header;
    uint32_t raw_cartificate_len = (cartificate.cert_length[0] << 16) | (cartificate.cert_length[1] << 8) | cartificate.cert_length[2];
    
    extract_public_key(&cartificate.cert.data()[3], cartificate.cert.size() - 3);

    // TODO: need to authenticate the cartificate before sending the premaster secret by using the public key and the

    // generate a random premaster secret
    uint8_t premaster_secret[48];
    RAND_bytes(premaster_secret, 48);

    // encrypt the premaster secret using the public key
    uint8_t encrypted_premaster_secret[256];
    RSA_public_encrypt(48, premaster_secret, encrypted_premaster_secret, p_rsa, RSA_PKCS1_PADDING);

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
  //  p_socket->send(key_exchange_buffer, key_exchange_buffer.size(), 0, 0);
   
 //   std::string data;
  //  uint8_t encrypted_data[48];

   // encrypted_handshake_msg.append(data);

    // extract master secret
    auto pre = std::vector<uint8_t>(premaster_secret, premaster_secret + 48);
    auto client_rand = std::vector<uint8_t>(client_msg.random.random_bytes, client_msg.random.random_bytes + 32);
    auto server_rand = std::vector<uint8_t>(server_hello.random.random_bytes, server_hello.random.random_bytes + 32);
    auto master_secret = extract_master_secret(pre, client_rand, server_rand);




    std::vector<uint8_t> client_write_key;
    std::vector<uint8_t> server_write_key;
    std::vector<uint8_t> client_write_iv;
    std::vector<uint8_t> server_write_iv;


    // Derive session keys
    derive_session_keys(master_secret, client_rand, server_rand, client_write_key, server_write_key, client_write_iv, server_write_iv);

    // Encrypt some data
    std::vector<uint8_t> plaintext;

    // concate all hanshake massages
    
    // add ckient hello header
    char* start_of_tls_header = (char*)&header;
   // plaintext.insert(plaintext.end(), start_of_tls_header, start_of_tls_header + sizeof(tls_header));

    // add client hello
    auto client_hello  = client_msg.parse();
    auto client_hello_msg = std::vector<uint8_t>(client_hello.begin(), client_hello.end());
    plaintext.insert(plaintext.end(), client_hello_msg.begin(), client_hello_msg.end());

    // add server hello + header
    auto server_hello_msg = std::vector<uint8_t>(start_of_server_hello, start_of_server_hello + ser_msg_len  - 1 + 5);

    plaintext.insert(plaintext.end(), server_hello_msg.begin(), server_hello_msg.end());

    // add server cartificate + header
    auto server_certificate = std::vector<uint8_t>(start_of_server_certificate , start_of_server_certificate + raw_cartificate_len + 3 - 1 + 5 );
    plaintext.insert(plaintext.end(), server_certificate.begin(), server_certificate.end());

    // add server hello done + header
    auto server_hello_done = std::vector<uint8_t>(start_of_server_hello_done, start_of_server_hello_done + 4);
    plaintext.insert(plaintext.end(), server_hello_done.begin(), server_hello_done.end()) ;

    // add client key exchange + header
    
   plaintext.insert(plaintext.end(), msg_to_send2.begin(), msg_to_send2.end());



    std::vector<uint8_t> hashedMessages(SHA384_DIGEST_LENGTH);
    SHA384(plaintext.data(), plaintext.size(), hashedMessages.data());
    std::vector<uint8_t> verifyData = construct_verify_data(master_secret, hashedMessages);


    verifyData.push_back(0x14);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x0c);

    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);
    verifyData.push_back(0x00);


    auto bca = encryptMessage(verifyData, client_write_key, client_write_iv);

    // create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);
    encrypted_handshake_header.length = htons(bca.size());

    std::string encrypted_handshake_msg;
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));
    encrypted_handshake_msg.append((char*)bca.data(),bca.size());
    // add to buffer
 //   encrypted_handshake_msg.insert(encrypted_handshake_msg.end(), verifyData.begin(), verifyData.end());
    key_exchange_buffer.append(encrypted_handshake_msg);


    // send client key exchange msg 
    p_socket->send(key_exchange_buffer, key_exchange_buffer.size(), 0, 0);

    std::cout << "finish send client key exchange" << std::endl;






}


void tls_socket::shutdown(int how) {
    // TODO: Implement shutdown method for TLS socket
}

void tls_socket::send(std::string uio, size_t uio_resid, size_t chunk, int flags) {
    // TODO: Implement send method for TLS socket
}

int tls_socket::recv(std::string& uio, size_t uio_resid, size_t chunk, int flags) {
    // TODO: Implement recv method for TLS socket
    return 0;
}

std::string tls_socket::encrypt(std::string& msg) const {
    // TODO: Implement encryption method for TLS socket
    return "";
}

std::string tls_socket::decrypt(std::string& msg) const {
    // TODO: Implement decryption method for TLS socket
    return "";
}


