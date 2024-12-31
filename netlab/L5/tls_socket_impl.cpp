#include "tls_socket.h"

#pragma warning(disable : 4996)
#define MAX_MTU    5000
#define TLS_HEADER_OFFSET 52 

using namespace netlab;

/************************************************************************/
/*                    tls_socket Class (Implementation)                 */
/************************************************************************/

// Constructor - Implemented for you.
tls_socket::tls_socket(inet_os& inet, bool server) : secure_socket(inet), server(server) { }

// Destructor - Implemented for you.
tls_socket::~tls_socket() { }

/*
    send Function - Sends a message to the TLS socket
    (Uses the send function of the L5_socket_impl class inside) - Implemented for you.
    Parameters:
        * uio - The message to send.
        * uio_resid - The length of the message.
        * chunk - The size of the message chunk.
        * flags - The flags to use.
*/
void tls_socket::send(std::string uio, size_t uio_resid, size_t chunk, int flags) {

    std::string encrypted_msg = encrypt(uio, server);

    // Create the encrypted handshake message.
    tls_header header;
    header.type = TLS_CONTENT_TYPE_APPLICATION_DATA;
    header.version = htons(TLS_VERSION_TLSv1_2);
    header.length = htons(encrypted_msg.size());

    char* buff = (char*)&header;

    encrypted_msg.insert(encrypted_msg.begin(), buff, buff + sizeof(tls_header));
    p_socket->send(encrypted_msg, encrypted_msg.size(), chunk, flags);
}

/*
    recv Function - Receives a message from the TLS socket
    (Uses the recv function of the L5_socket_impl class inside) - Implemented for you.
    Parameters:
        * uio - The message to receive.
        * uio_resid - The length of the message.
        * chunk - The size of the message chunk.
        * flags - The flags to use.
*/
int tls_socket::recv(std::string& uio, size_t uio_resid, size_t chunk, int flags) {

    std::string recv_buffer;
    int bytes_recived = p_socket->recv(recv_buffer, uio_resid + TLS_HEADER_OFFSET, chunk, flags);

    // Get the TLS header.
    tls_header* recv_header = (tls_header*)recv_buffer.c_str();

    // Get the start of the encrypted data.
    char* start_of_encrypted_data = (char*)recv_buffer.c_str() + sizeof(tls_header);

    auto len = ntohs(recv_header->length);

    std::string encrtped_msg(start_of_encrypted_data, start_of_encrypted_data + len);

    uio = decrypt(encrtped_msg, server);

    return 0;
}

/*
    connect Function -
        Establishes a secure TLS connection to a specified address.
        This function performs the following steps:
        1. Establishes a TCP connection to the specified address (using the connect function of the L5_socket_impl class).
        2. Initiates the TLS handshake process by sending a ClientHello message.
        3. Receives a ServerHello message from the server, along with the server's certificate and ServerHelloDone message.
        4. Extracts the server's public key from the certificate and verifies the certificate.
        5. Client key exchange: Generates a pre-master secret, encrypts it using the server's public key, and sends it to the server.
        6. Sends a ChangeCipherSpec message to indicate that the client is ready to switch to the negotiated cipher suite.
        7. Completes the handshake process by exchanging Finished messages with the server.

    Parameters:
    * name - The address to connect to.
    * name_len - The length of the address.
*/
void tls_socket::connect(const struct sockaddr* name, int name_len) {

    // First establish tcp connection
    p_socket->connect(name, name_len);

    // Prepare client hello
    HandshakeType msg_type = CLIENT_HELLO;
    TLSHandshakeProtocol client_hello;
    client_hello.handshake.configureHandshakeBody(msg_type);
    client_hello.updateHandshakeProtocol(msg_type);

    // Send client hello
    std::string client_hello_msg = client_hello.serialize_handshake_protocol_data(msg_type);
    p_socket->send(client_hello_msg, client_hello_msg.size(), 0, 0);

    // Recive server hello, certificate, server hello done
    std::string recv_buffer;
    p_socket->recv(recv_buffer, MAX_MTU, 1, 0);

    msg_type = SERVER_HELLO;
    TLSHandshakeProtocol server_hello;
    server_hello.handshake.configureHandshakeBody(msg_type);
    server_hello.deserialize_handshake_protocol_data(recv_buffer, msg_type);

    msg_type = CERTIFICATE;
    TLSHandshakeProtocol recive_cartificate;
    recive_cartificate.handshake.configureHandshakeBody(msg_type);
    std::string frr(recv_buffer.begin() + server_hello.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH, recv_buffer.end());
    recive_cartificate.deserialize_handshake_protocol_data(frr, msg_type);
    extract_public_key(recive_cartificate.handshake.body.certificate->certificate_list[0].data(), recive_cartificate.handshake.body.certificate->certificate_list[0].size());

    msg_type = SERVER_HELLO_DONE;
    TLSHandshakeProtocol serv_hello_done;
    serv_hello_done.handshake.configureHandshakeBody(msg_type);
    std::string frr2(frr.begin() + recive_cartificate.TLS_record_layer.length + RECORD_LAYER_DEFAULT_LENGTH, frr.end());
    serv_hello_done.deserialize_handshake_protocol_data(frr2, msg_type);

    // Create the client key exchange , change cipher spce, client finish
    msg_type = CLIENT_KEY_EXCHANGE;
    TLSHandshakeProtocol client_key_exchange;
    client_key_exchange.handshake.configureHandshakeBody(msg_type);
    client_key_exchange.handshake.body.clientKeyExchange->key_exchange_algorithm = KEY_EXCHANGE_ALGORITHM_RSA;
    client_key_exchange.handshake.body.clientKeyExchange->createClientKeyExchange();
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.major = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.client_version.minor = 0x03;
    client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret.random = generate_random_bytes<PRE_MASTER_SECRET_RND_SIZE>();

    unsigned char pre[MASTER_SECRET_SIZE];
    unsigned char encrypt_pre[PRE_MASTER_SECRET_ENCRYPTED_SIZE];

    memcpy(pre, &client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.pre_master_secret, sizeof(PreMasterSecret));
    RSA_public_encrypt(48, pre, encrypt_pre, p_rsa, RSA_PKCS1_PADDING);
    std::copy(std::begin(encrypt_pre), std::end(encrypt_pre), client_key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.begin());

    client_key_exchange.updateHandshakeProtocol(msg_type);
    std::string client_key_msg = client_key_exchange.serialize_handshake_protocol_data(msg_type);

    // Change cipher massage
    ChangeCipherSpec changeCipherSpec;
    changeCipherSpec.setChangeCipherSpec();

    // Derive master secret
    std::string client_rand = client_hello.handshake.body.clientHello->random.get_random();
    std::string server_rand = server_hello.handshake.body.clientHello->random.get_random();
    std::vector<uint8_t> pre_master_vec(pre, pre + MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec = derive_master_secret(pre_master_vec, client_rand, server_rand);

    // Key deriviation
    derive_keys(master_secret_vec, client_rand, server_rand);

    // Prepare hanshake massages
    std::vector<uint8_t> plaintext;
    std::string client_hello_body(client_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_hello_msg.end());
    plaintext.insert(plaintext.end(), client_hello_body.begin(), client_hello_body.end()); // Add ClientHello
    std::string server_hello_msg = server_hello.serialize_handshake_protocol_data(SERVER_HELLO);
	plaintext.insert(plaintext.end(), server_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_msg.end()); // Add ServerHello
    std::string server_certificate = recive_cartificate.serialize_handshake_protocol_data(CERTIFICATE);
	plaintext.insert(plaintext.end(), server_certificate.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_certificate.end());  // Add Certificate
    std::string server_hello_done_msg = serv_hello_done.serialize_handshake_protocol_data(SERVER_HELLO_DONE);
	plaintext.insert(plaintext.end(), server_hello_done_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_done_msg.end());   // Add ServerHelloDone
	plaintext.insert(plaintext.end(), client_key_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_key_msg.end()); // ClientKeyExchange

    // Derive verify data
    uint8_t hash_msg[SHA256_HASH_LEN];
    SHA256(plaintext.data(), plaintext.size(), hash_msg);
    std::vector<uint8_t> seed2(hash_msg, hash_msg + SHA256_HASH_LEN);
    uint8_t verify_data[VERIFY_DATA_LEN];
    prf(seed2, "client finished", master_secret_vec, verify_data, VERIFY_DATA_LEN);

    // Compose message to encrypt
    std::vector<uint8_t> final_msg = { FINISHED, 0x00 , 0x00 , VERIFY_DATA_LEN };
    final_msg.insert(final_msg.end(), verify_data, verify_data + VERIFY_DATA_LEN);

    // Encrypt final msg
    std::string final_msg_str(final_msg.begin(), final_msg.end());
    std::string encrypted_final_msg = encrypt(final_msg_str);

    // Create encrypted handshake msg
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONTENT_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);
    encrypted_handshake_header.length = htons(64);

    std::string encrypted_handshake_msg;
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));

    // Add to buffer
    encrypted_handshake_msg.insert(encrypted_handshake_msg.end(), encrypted_final_msg.begin(), encrypted_final_msg.end());

    std::string key_exchange_buffer;
    key_exchange_buffer.append(client_key_msg);
    key_exchange_buffer.append(changeCipherSpec.serialize_change_cipher_spec_data());
    key_exchange_buffer.append(encrypted_handshake_msg);

    // Send client key exchange msg 
    p_socket->send(key_exchange_buffer, key_exchange_buffer.size(), 0, 0);

    recv_buffer.clear();
    p_socket->recv(recv_buffer, MAX_MTU, 1, 0);

    // Verify the server change cipher spec msg
    tls_header* recv_header2 = (tls_header*)recv_buffer.c_str();
    if (ntohs(recv_header2->version) != TLS_VERSION_TLSv1_2) {
        std::cout << "Version doesn't match!" << std::endl;
        return;
    }

    // Get encrypted handshake message
    char* start_of_encrypted_handshake = (char*)recv_buffer.c_str() + sizeof(tls_header) + 1;
    tls_header* encrypted_handshake_header1 = (tls_header*)start_of_encrypted_handshake;
    uint32_t encrypted_handshake_len = 64;
    char* start_of_encrypted_handshake_msg = start_of_encrypted_handshake + sizeof(tls_header);

    // Decrypt the message
    std::string decrypted = decrypt(std::string(start_of_encrypted_handshake_msg, start_of_encrypted_handshake_msg + encrypted_handshake_len));

    // Derive server verify data for verification
    plaintext.insert(plaintext.end(), final_msg.begin(), final_msg.end());
    uint8_t hash_msg2[SHA256_HASH_LEN];
    SHA256(plaintext.data(), plaintext.size(), hash_msg2);
    std::vector<uint8_t> seed23(hash_msg2, hash_msg2 + SHA256_HASH_LEN);
    uint8_t server_verify_data[VERIFY_DATA_LEN];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, VERIFY_DATA_LEN);

    return;
}

/*
    handshake Function -
    Performs the TLS handshake process to establish a secure connection.
    This process includes the following steps:
    1. Receiving a ClientHello message from the client, which includes the client's supported cipher suites and TLS version.
    2. Begins to create a buffer to store the handshake messages - ServerHello, Certificate, ServerHelloDone.
    3. Creates the ServerHello message, which includes the selected cipher suite, TLS version, and server random value
    - and adds it to the buffer.
    4. Creates the Certificate message, which includes the server's certificate - and adds it to the buffer.
    5. Creates the ServerHelloDone message - and adds it to the buffer.
    6. Sends the buffer to the client.
    7. Receives the ClientKeyExchange message from the client, which includes the pre-master secret encrypted with the server's public key.
    8. Decrypts the pre-master secret using the server's private key.
    9. Derives the master secret from the pre-master secret and the client and server random values.
    10. Derives the keys from the master secret and the client and server random values.
    11. Sends a ChangeCipherSpec message to indicate that the server is ready to switch to the negotiated cipher suite.
    12. Completes the handshake process by exchanging Finished messages with the client.
*/
void tls_socket::handshake() {
    // Handle handshake
    std::string recv_buffer;
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
    key_exchange.deserialize_handshake_protocol_data(recv_buffer2, msg_type);

    // Decrypt the premaster secret
    uint8_t decrypted_premaster_secret[MASTER_SECRET_SIZE];
    rsa_decrypt(decrypted_premaster_secret, key_exchange.handshake.body.clientKeyExchange->client_exchange_keys.encryptedPreMasterSecret.encrypted_pre_master_secret.data());

    // Derive master secret
    std::string client_rand = client_hello.handshake.body.clientHello->random.get_random();
    std::string server_rand = server_hello.handshake.body.clientHello->random.get_random();
    std::vector<uint8_t> pre_master_vec(decrypted_premaster_secret, decrypted_premaster_secret + MASTER_SECRET_SIZE);
    std::vector<uint8_t> master_secret_vec = derive_master_secret(pre_master_vec, client_rand, server_rand);

    // Key deriviation
    derive_keys(master_secret_vec, client_rand, server_rand);

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
    handshake_msg.insert(handshake_msg.end(), recv_buffer.begin() + RECORD_LAYER_DEFAULT_LENGTH, recv_buffer.begin() + RECORD_LAYER_DEFAULT_LENGTH + client_hello.TLS_record_layer.length); // client hello
    handshake_msg.insert(handshake_msg.end(), server_hello_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_hello_msg.end());
    handshake_msg.insert(handshake_msg.end(), certificate_msg.begin() + RECORD_LAYER_DEFAULT_LENGTH, certificate_msg.end());
    handshake_msg.insert(handshake_msg.end(), server_done.begin() + RECORD_LAYER_DEFAULT_LENGTH, server_done.end());

    std::string client_ket_exchange = key_exchange.serialize_handshake_protocol_data(CLIENT_KEY_EXCHANGE);
    handshake_msg.insert(handshake_msg.end(), client_ket_exchange.begin() + RECORD_LAYER_DEFAULT_LENGTH, client_ket_exchange.end());

    // Verify the client verify data
    uint8_t hash_msg[SHA256_HASH_LEN];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg);
    std::vector<uint8_t> seed2(hash_msg, hash_msg + SHA256_HASH_LEN);
    uint8_t verify_data[VERIFY_DATA_LEN];
    prf(seed2, "client finished", master_secret_vec, verify_data, VERIFY_DATA_LEN);

    // Change cipher massage
    ChangeCipherSpec changeCipherSpec2;
    changeCipherSpec2.setChangeCipherSpec();

    // Derive server's verify data for verification
    handshake_msg.insert(handshake_msg.end(), client_verify_data.begin(), client_verify_data.end());
    uint8_t hash_msg2[SHA256_HASH_LEN];
    SHA256(handshake_msg.data(), handshake_msg.size(), hash_msg2);
    std::vector<uint8_t> seed23(hash_msg2, hash_msg2 + SHA256_HASH_LEN);
    uint8_t server_verify_data[VERIFY_DATA_LEN];
    prf(seed23, "server finished", master_secret_vec, server_verify_data, VERIFY_DATA_LEN);

    // Create the encrypted handshake message
    tls_header encrypted_handshake_header;
    encrypted_handshake_header.type = TLS_CONTENT_TYPE_HANDSHAKE;
    encrypted_handshake_header.version = htons(TLS_VERSION_TLSv1_2);

    // Compose message to encrypt
    std::vector<uint8_t> final_msg = { FINISHED, 0x00 , 0x00 , VERIFY_DATA_LEN };
    final_msg.insert(final_msg.end(), server_verify_data, server_verify_data + VERIFY_DATA_LEN);

    // Encrypt the final message
    std::string final_msg_str(final_msg.begin(), final_msg.end());
    std::string encrypted_final_msg = encrypt(final_msg_str, true);

    encrypted_handshake_header.length = htons(encrypted_final_msg.size());

    std::string encrypted_handshake_msg;

    // Add change cipher spec
    encrypted_handshake_msg.append(changeCipherSpec2.serialize_change_cipher_spec_data());
    encrypted_handshake_msg.append((char*)&encrypted_handshake_header, sizeof(encrypted_handshake_header));
    encrypted_handshake_msg.append(encrypted_final_msg);

    p_socket->send(encrypted_handshake_msg, encrypted_handshake_msg.size(), 0, 0);
}