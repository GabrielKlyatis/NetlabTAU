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
#include <stdio.h>
#include <stdint.h>
extern "C" {
#include <openssl/applink.c>
}

#pragma warning(disable : 4996)

using namespace netlab;


std::vector<unsigned char> encryptAES_CBC(const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx;
    std::vector<unsigned char> ciphertext;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Error creating cipher context" << std::endl;
        return ciphertext;
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()) != 1) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    // Perform the encryption
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE); // Allocate space for padding
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "Error performing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize ciphertext to actual length
    ciphertext.resize(ciphertext_len);

    return ciphertext;
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
   
    client_msg.cipher_suites = { 0x2f00, 0xff00};

    
    client_msg.compression_methods = { NULL_COMPRESSION };

    client_msg.extensions = {};

    // set header length
    
    
    //uint32_t msg_len = sizeof(TLSHello) - 3;
    uint32_t msg_len = 45 - 3 - 5 + 6;
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
    std::cout << std::hex << msg_to_send ;
    std::cout << std::endl << "sizeof client msg" << msg_to_send.size() << std::endl;

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
   
     // Get RSA key size
    int rsa_size = RSA_size(p_rsa);
    int key_bits = RSA_bits(p_rsa);

    uint8_t premaster_secret[48];
    RAND_bytes(premaster_secret, 48);
    premaster_secret[0] = 0x03;
    premaster_secret[1] = 0x03; 


    // encrypt the premaster secret using the public key
    uint8_t encrypted_premaster_secret[256];
    int rt = RSA_public_encrypt(48, premaster_secret, encrypted_premaster_secret, p_rsa, RSA_PKCS1_PADDING);
    std::cout << "encrypted premaster secret" << std::endl;
    

    std::ofstream myfile;
    myfile.open("C:\\Projects\\example.txt");
    FILE* file = fopen("C:\\Projects\\example.bin", "wb");
    for (auto val : encrypted_premaster_secret)
    {
        std::cout << val;
    
    }
    fwrite(encrypted_premaster_secret, sizeof(uint8_t), 256, file);
    std::cout << std::endl;
    //myfile << "Writing this to a file.\n";
    myfile.close();
    fclose(file);









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
    auto rands = std::vector<uint8_t>(client_msg.random.random_bytes, client_msg.random.random_bytes + 32);
    rands.insert(rands.end(), server_hello.random.random_bytes, server_hello.random.random_bytes + 32);

    unsigned char master_secret[48];

    // create master sercret 
     EVP_PKEY_CTX *pctx;
     unsigned char out[10];
     size_t outlen = sizeof(master_secret);

     pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
     if (EVP_PKEY_derive_init(pctx) <= 0) return;
         /* Error */
     if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) return;
         /* Error */
     if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, premaster_secret, 48) <= 0) return;
         /* Error */
     if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, rands.data(), rands.size()) <= 0) return;
         /* Error */
     if (EVP_PKEY_derive(pctx, master_secret, &outlen) <= 0)
         /* Error */



    std::vector<uint8_t> client_write_key1;
    std::vector<uint8_t> server_write_key1;
    std::vector<uint8_t> client_write_iv1;
    std::vector<uint8_t> server_write_iv1;


    // Derive session keys
    //derive_session_keys(master_secret, client_rand, server_rand, client_write_key1, server_write_key1, client_write_iv1, server_write_iv1);

    // Encrypt some data
    std::vector<uint8_t> plaintext;

    // concate all hanshake massages
    

    // add client hello
    auto client_hello  = client_msg.parse();
    auto client_hello_msg = std::vector<uint8_t>(client_hello.begin(), client_hello.end());
    plaintext.insert(plaintext.end(), client_hello_msg.begin(), client_hello_msg.end());

    // add server hello
    auto server_hello_msg = std::vector<uint8_t>(start_of_server_hello, start_of_server_hello + ser_msg_len  - 1 + 5);
    plaintext.insert(plaintext.end(), server_hello_msg.begin(), server_hello_msg.end());

    // add server cartificate
    auto server_certificate = std::vector<uint8_t>(start_of_server_certificate , start_of_server_certificate + raw_cartificate_len + 3 - 1 + 5 );
    plaintext.insert(plaintext.end(), server_certificate.begin(), server_certificate.end());

    // add server hello done 
    auto server_hello_done = std::vector<uint8_t>(start_of_server_hello_done, start_of_server_hello_done + 4);
    plaintext.insert(plaintext.end(), server_hello_done.begin(), server_hello_done.end()) ;

    // add client key exchange
    plaintext.insert(plaintext.end(), msg_to_send2.begin(), msg_to_send2.end());


    // ________________________________
     // Compute SHA384 hash of the handshake messages
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len;
   // EVP_Digest(plaintext.data(), plaintext.size(), hash.data(), &hash_len, EVP_sha384(), nullptr);
   // hash.resize(hash_len);


    unsigned char verify_data[12];
    auto master_vec = std::vector<unsigned char>(master_secret, master_secret + 48);
  //  verify_client_finished(master_vec, plaintext, verify_data);



    // PRF to generate verify data for the Finished message
    //std::vector<unsigned char> verify_data = PRF(master_secret, "client finished", hash, 12);


    std::vector<unsigned char> verify_data1{ 0x14 , 0x00, 0x00, 0x0c };
    verify_data1.insert(verify_data1.end(), verify_data, verify_data + 12);

  //  std::vector<unsigned char> ciphertext = encryptAES_CBC(client_write_key1, client_write_iv1, plaintext);

    // Derive key block
    std::vector<unsigned char> seed;
    seed.insert(seed.end(), client_rand.begin(), client_rand.end());
    seed.insert(seed.end(), server_rand.begin(), server_rand.end());
    unsigned char key_block[72];
 

    // Extract keys and IVs from the key block
    std::vector<unsigned char> client_write_key(key_block, key_block + 32);
    std::vector<unsigned char> server_write_key(key_block + 32, key_block + 64);
    std::vector<unsigned char> client_write_iv(key_block + 64, key_block + 68);
    std::vector<unsigned char> server_write_iv(key_block+ 68, key_block + 72);

    // Generate explicit nonce (8 bytes)
    std::vector<unsigned char> explicit_nonce(8);
    RAND_bytes(explicit_nonce.data(), explicit_nonce.size());

    // Concatenate the client_write_iv (4 bytes) and explicit_nonce (8 bytes) to form the full IV
    std::vector<unsigned char> full_iv(client_write_iv);
    full_iv.insert(full_iv.end(), explicit_nonce.begin(), explicit_nonce.end());

    // Encrypt the verify data using client_write_key and client_write_iv
    std::vector<unsigned char> tag;
  //  std::vector<unsigned char> ciphertext = encrypt_aes_gcm(verify_data1, client_write_key, full_iv, tag);

    // Output the encrypted handshake message (IV + ciphertext + tag)
    std::vector<unsigned char> encrypted_handshake_message;
    encrypted_handshake_message.insert(encrypted_handshake_message.end(), explicit_nonce.begin(), explicit_nonce.end());
    //encrypted_handshake_message.insert(encrypted_handshake_message.end(), ciphertext.begin(), ciphertext.end());
    encrypted_handshake_message.insert(encrypted_handshake_message.end(), tag.begin(), tag.end());




   /* std::vector<uint8_t> hashedMessages(SHA384_DIGEST_LENGTH);
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
    verifyData.push_back(0x00);*/


   // auto bca = encryptMessage(verifyData, client_write_key, client_write_iv);

    // create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONNECTION_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);
    encrypted_handshake_header.length = htons(encrypted_handshake_message.size());

    std::string encrypted_handshake_msg;
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));
    encrypted_handshake_msg.append((char*)encrypted_handshake_message.data(), encrypted_handshake_message.size());
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


