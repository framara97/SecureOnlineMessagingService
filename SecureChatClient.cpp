#include "SecureChatClient.h"
#include <cstring>
#include <iostream>
#include <thread>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

string SecureChatClient::username;
unsigned int SecureChatClient::choice;
unsigned char SecureChatClient::logout_nonce[NONCE_SIZE];
EVP_PKEY* SecureChatClient::client_prvkey = NULL;
X509* SecureChatClient::ca_certificate = NULL;
X509_CRL* SecureChatClient::ca_crl = NULL;

SecureChatClient::SecureChatClient(string client_username, const char *server_addr, unsigned short int server_port) {
    if (client_username.length() > USERNAME_MAX_SIZE){ cerr<<"ERR: Username too long."<<endl; exit(1); }
    if (strlen(server_addr) > MAX_ADDRESS_SIZE){ cerr<<"ERR: Server address out of bound."<<endl; }

    /* ---------------------------------------------------------- *\
    |* Set client username                                        *|
    \* ---------------------------------------------------------- */
    username = client_username;

    /* ---------------------------------------------------------- *\
    |* Get client private key                                     *|
    \* ---------------------------------------------------------- */
    client_prvkey = getPrvKey();

    /* ---------------------------------------------------------- *\
    |* Read the CA certificate                                    *|
    \* ---------------------------------------------------------- */
    ca_certificate = getCertificate();

    /* ---------------------------------------------------------- *\
    |* Read the CRL                                               *|
    \* ---------------------------------------------------------- */
    ca_crl = getCRL();

    
    /* ---------------------------------------------------------- *\
    |* Set the server address and the server port in the          *|
    |* class instance                                             *|
    \* ---------------------------------------------------------- */
    strncpy(this->server_address, server_addr, MAX_ADDRESS_SIZE-1);
    this->server_address[MAX_ADDRESS_SIZE-1] = '\0';
    this->server_port = server_port;

    /* ---------------------------------------------------------- *\
    |* Setup the server socket                                    *|
    \* ---------------------------------------------------------- */
    setupServerSocket(server_port, server_addr);

    /* ---------------------------------------------------------- *\
    |* Receive server certificate (S1)                            *|
    \* ---------------------------------------------------------- */
    cout<<"LOG: Starting Key Establishment with the server"<<endl;
    unsigned char* R_server = receiveCertificate();
    cout<<"LOG: Message S1 received"<<endl;
    //TODO: salvare in due variabili TpubK e TprivK chiavi effimere con il server
    /* ---------------------------------------------------------- *\
    |* Verify server certificate                                  *|
    \* ---------------------------------------------------------- */
    verifyCertificate();

    string input;

    cout<<"LOG: Do you want to"<<endl<<"    0: Send a message"<<endl<<"    1: Receive a message"<<endl<<"    q: Logout"<<endl;
    cout<<"LOG: Select a choice: ";
    cin>>input;
    if(!cin){exit(1);}
    while(1){
        if(input.compare("0")!=0 && input.compare("1")!=0 && input.compare("q")!=0){
            cout<<"LOG: Choice not valid! Choose 0, 1 or 2!"<<endl;
            cin>>input;
            if(!cin){exit(1);}
        } else break;
    }

    if(input.compare("q")==0){
        /* ---------------------------------------------------------- *\
        |* non-authenticated logout                                   *|
        \* ---------------------------------------------------------- */
        logout(0); 
        exit(0);
    }
    choice = input.c_str()[0]-'0';

    /* ---------------------------------------------------------- *\
    |* Generating TpubK e TprvK                                   *|
    \* ---------------------------------------------------------- */
    EVP_PKEY* tprivk = Utility::generateTprivK(this->username);
    EVP_PKEY* tpubk = Utility::generateTpubK(this->username);
    Utility::removeTprivK(this->username);
    Utility::removeTpubK(this->username);

    /* ---------------------------------------------------------- *\
    |* Send a message to authenticate to the server (S2)          *|
    \* ---------------------------------------------------------- */
    unsigned char* R_user;
    R_user = (unsigned char*)malloc(R_SIZE);
    if (!R_user){cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1);}
    authenticateUser(choice, R_server, tpubk, R_user);
    cout<<"LOG: Message S2 sent"<<endl;

    unsigned char* iv;
    unsigned char* K = receiveS3Message(iv, tprivk, R_user);
    cout<<"LOG: Message S3 received"<<endl;

    setCounters(iv);
    storeK(K);

    unsigned int response;
    EVP_PKEY* peer_key;

    /* ---------------------------------------------------------- *\
    |* client wants to send a message                             *|
    \* ---------------------------------------------------------- */
    if(choice == 0){ 
        /* ---------------------------------------------------------- *\
        |* Print the user list and select a user to communicate with  *|
        \* ---------------------------------------------------------- */
        string selected_user = receiveAvailableUsers();
        /* ---------------------------------------------------------- *\
        |* Send request to talk to the selected user                  *|
        \* ---------------------------------------------------------- */
        sendRTT(selected_user);

        /* ---------------------------------------------------------- *\
        |* Wait for the answer to the previous RTT                    *|
        \* ---------------------------------------------------------- */
        response = waitForResponse();

        if(response==1){
            /* ---------------------------------------------------------- *\
            |* Wait for the selected_user public key                      *|
            \* ---------------------------------------------------------- */
            peer_key = receiveUserPubKey(selected_user);

            /* ---------------------------------------------------------- *\
            |* Handle key establishment                                   *|
            \* ---------------------------------------------------------- */
            senderKeyEstablishment(selected_user, peer_key);
        }
    }
    /* ---------------------------------------------------------- *\
    |* client wants to receive a message                          *|
    \* ---------------------------------------------------------- */ 
    else if(choice == 1){ 
        string sender_username = waitForRTT();
        string input;

        cout<<"LOG: "<<sender_username<<" wants to send you a message. Do you want to "<<endl<<"    0: Refuse"<<endl<<"    1: Accept"<<endl;
        cout<<"LOG: Select a choice: ";
        cin>>input;
        if(!cin){exit(1);}
        while(1){
            if(input.compare("0")!=0 && input.compare("1")!=0){
                cout<<"LOG: Choice not valid! Choose 0 or 1!"<<endl;
                cin>>input;
                if(!cin){exit(1);}
            } else break;
        }

        response = input.c_str()[0]-'0';

        sendResponse(sender_username, response);

        if(response==1){
            /* ---------------------------------------------------------- *\
            |* Wait for the selected_user public key                      *|
            \* ---------------------------------------------------------- */
            peer_key = receiveUserPubKey(sender_username);

            /* ---------------------------------------------------------- *\
            |* Handle key establishment                                   *|
            \* ---------------------------------------------------------- */
            receiverKeyEstablishment(sender_username, peer_key);
        }
    }
    exit(0);
};

EVP_PKEY* SecureChatClient::getPrvKey() {
    string path = "./client/" + username + "/" + username + "_key_password.pem";
    client_prvkey = Utility::readPrvKey(path.c_str(), NULL);
    return client_prvkey;
}

X509* SecureChatClient::getCertificate(){
    string path = "./client/" + username + "/ca_cert.pem";
    ca_certificate = Utility::readCertificate(path.c_str());
    return ca_certificate;
}

X509_CRL* SecureChatClient::getCRL(){
    string path = "./client/" + username + "/ca_crl.pem";
    ca_crl = Utility::readCRL(path.c_str());
    return ca_crl;
}

void SecureChatClient::setupServerAddress(unsigned short int port, const char *addr){
    memset(&(this->server_addr), 0, sizeof(this->server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	inet_pton(AF_INET, addr, &(this->server_addr.sin_addr));
}

void SecureChatClient::setupServerSocket(unsigned short int server_port, const char *addr){
    this->server_socket = socket(AF_INET, SOCK_STREAM, 0);
	setupServerAddress(server_port, addr);

	if (connect(this->server_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){ cerr<<"ERR: Error in the connect"<<endl; exit(1); }
    cout<<"LOG: Connected to the server"<<endl;
}

unsigned char* SecureChatClient::receiveCertificate(){
    unsigned char* buf = (unsigned char*)malloc(S1_SIZE);
    if (!buf){
        cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    
    cout<<"LOG: Waiting for certificate"<<endl;
    unsigned int len = recv(this->server_socket, (void*)buf, S1_SIZE, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the certificate"<<endl; exit(1); }
    cout<<"LOG: Certificate received"<<endl;

    unsigned char* R_server = (unsigned char*)malloc(R_SIZE);
    if (!R_server){
        cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    if (len < R_SIZE) { cerr<<"ERR: Access out-of-bound1"<<endl; exit(1); }
    memcpy(R_server, buf, R_SIZE);

    if (R_SIZE + (unsigned long)buf < R_SIZE) { cerr<<"Thread "<<gettid()<<": Wrap around"<<endl; exit(1); }
    if (len > S1_SIZE) { cerr<<"ERR: Access out-of-bound2"<<endl; exit(1); }
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, buf+R_SIZE, CERTIFICATE_MAX_SIZE);
    this->server_certificate = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return R_server;
}

void SecureChatClient::verifyCertificate(){
    const char* correct_owner_name = "/C=IT/CN=Server";
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_certificate);
    X509_STORE_add_crl(store, ca_crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, this->server_certificate, NULL);
    if(X509_verify_cert(ctx) != 1) {  cerr<<"ERR: The certificate of the server is not valid"<<endl; exit(1); }

    X509_NAME* owner_name = X509_get_subject_name(this->server_certificate);
    char* tmpstr = X509_NAME_oneline(owner_name, NULL, 0);
    free(owner_name);
    if(strcmp(tmpstr, correct_owner_name) != 0){ cerr<<"ERR: The certificate of the server is not valid"<<endl; exit(1);  }

    this->server_pubkey = X509_get_pubkey(this->server_certificate);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}


EVP_PKEY* SecureChatClient::receiveUserPubKey(string username){
    /* ---------------------------------------------------------- *\
    |* 5 | pubkey(451) | signature(256)                           *|
    \* ---------------------------------------------------------- */
    char* enc_buf = (char*)malloc(PUBKEY_MSG_SIZE+ENC_FIELDS);
    if (!enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)enc_buf, PUBKEY_MSG_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }

    unsigned char* pubkey_buf = (unsigned char*)malloc(PUBKEY_MSG_SIZE);
    if (!pubkey_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)enc_buf);
    if (Utility::decryptSessionMessage(pubkey_buf, (unsigned char*)enc_buf, len, this->K, buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };

    if (pubkey_buf[0] != 5){ cerr<<"ERR: Message type is not corresponding to 'pubkey type'."<<endl; exit(1); }
    cout<<"LOG: Public key received from "<<username<<endl;

    if (1 + (unsigned long)pubkey_buf < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (buf_len < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, pubkey_buf+1, buf_len-1);
    EVP_PKEY* peer_pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return peer_pubkey;
}

void SecureChatClient::authenticateUser(unsigned int choice, unsigned char* R_server, EVP_PKEY* tpubk, unsigned char* &R_user){
    //TODO: aggiungere nonce_user e tpubk da mandare in chiaro al server
    //firmare nonce_server tpubk e ruolo
    /* ---------------------------------------------------------- *\
    |* Create message R_user                                      *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    RAND_bytes(R_user, R_SIZE);

    if (username.length() >= USERNAME_MAX_SIZE){ cerr<<"ERR: Username length too large."<<endl; exit(1); }

    /* ------------------------------------------------------------------------------- *\
    |*0/1| nonce_server(16) | nonce_user(16) | tpubk(451) | username_len(1) | username(MAX=16) | signature(256)*|
    \* ------------------------------------------------------------------------------- */
    char msg[S2_SIZE];
    /* ---------------------------------------------------------- *\
    |* Type = choice(0,1), authentication message with 0          *|
    |* to send message or 1 to receive message                    *|
    \* ---------------------------------------------------------- */
    msg[0] = choice; 
    unsigned int len = 1;
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, R_server, 0, R_SIZE, R_SIZE);
    len += R_SIZE;

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, tpubk);
    char* pubkey_buf = NULL;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    cout<<"Pubkey length: "<<pubkey_size<<endl;
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, (unsigned char*)&pubkey_size, 0, sizeof(long), sizeof(long));
    len += sizeof(long);
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, (unsigned char*)pubkey_buf, 0, pubkey_size, pubkey_size);
    BIO_free(mbio);
    len += pubkey_size;

    unsigned int to_sign_len = len;
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, R_user, 0, R_SIZE, R_SIZE);
    len += R_SIZE;

    unsigned int username_len = username.length(); 
    msg[len] = username_len;
    if (1 + len < 1){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    len++;
    
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, (unsigned char*)username.c_str(), 0, username_len, username_len);
    len += username_len;

    unsigned char* signature;
    unsigned int signature_len;

    Utility::signMessage(client_prvkey, msg, to_sign_len, &signature, &signature_len);
    Utility::secure_memcpy((unsigned char*)msg, len, S2_SIZE, (unsigned char*)signature, 0, SIGNATURE_SIZE, signature_len);
    memcpy(msg + len, signature, signature_len);
    len += signature_len;
    
    if (send(this->server_socket, msg, len, 0) < 0){
		cerr<<"ERR: Error in the sendto of the authentication message."<<endl;
		exit(1);
	}
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function receives the message S3 from the server.     *|
|* Returns K, namely the session key betweem client and server*|
|*                                                            *|
\* ---------------------------------------------------------- */
unsigned char* SecureChatClient::receiveS3Message(unsigned char* &iv, EVP_PKEY* tprivk, unsigned char* R_user){
    /* ---------------------------------------------------------- *\
    |* Receive the message                                        *|
    \* ---------------------------------------------------------- */
    char* buf = (char*)malloc(S3_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)buf, S3_SIZE, 0);
    if (len < 1){ cerr<<"ERR: Error in receiving the S3 message"<<endl; exit(1); }

    if (buf[0] != 1){
        cerr<<"ERR: Message type is not corresponding to S3"<<endl;
        exit(1);
    }
    /* ---------------------------------------------------------- *\
    |* Verify the authenticity of the message                     *|
    \* ---------------------------------------------------------- */
    if ((unsigned long)buf + R_SIZE < R_SIZE){ cerr<<"Wrap around"<<endl; exit(1); }
    if (len < SIGNATURE_SIZE){ cerr<<"Access out-of-bound"<<endl; exit(1); }
    if ((unsigned long)buf + len < len){ cerr<<"Wrap around"<<endl; exit(1); }
    if(Utility::verifyMessage(this->server_pubkey, buf+1, R_SIZE, (unsigned char*)((unsigned long)buf+len-SIGNATURE_SIZE), SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error while receiving the S3 message"<<endl;
        exit(1);
    }

    unsigned char R_user_received[R_SIZE];
    Utility::secure_memcpy(R_user_received, 0, R_SIZE, (unsigned char*)buf, 1, S3_SIZE, R_SIZE);
    if (Utility::compareR(R_user_received, R_user) == false){
        cerr<<"ERR: R_user not corrisponding"<<endl;
        exit(1);
    }

    /* ---------------------------------------------------------- *\
    |* Initialize variables for decrypting                        *|
    \* ---------------------------------------------------------- */
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    unsigned int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned int encrypted_key_len = EVP_PKEY_size(tprivk);
    unsigned int cphr_size = 2*BLOCK_SIZE;
    unsigned int plaintext_len;
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    iv = (unsigned char*)malloc(iv_len);
    unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
    unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
    if(!encrypted_key || !iv || !ciphertext || !plaintext) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }    

    /* ---------------------------------------------------------- *\
    |* Insert the fields from S3 into the respective variables    *|
    \* ---------------------------------------------------------- */
    unsigned int index = 1+R_SIZE;
    Utility::secure_memcpy(ciphertext, 0, cphr_size, (unsigned char*)buf, index, S3_SIZE, cphr_size);
    index += cphr_size;
    Utility::secure_memcpy(iv, 0, iv_len, (unsigned char*)buf, index, S3_SIZE, iv_len);
    index += iv_len;
    Utility::secure_memcpy(encrypted_key, 0, encrypted_key_len, (unsigned char*)buf, index, S3_SIZE, encrypted_key_len);

    /* ---------------------------------------------------------- *\
    |* Decrypt the message                                        *|
    \* ---------------------------------------------------------- */
    if (!Utility::decryptMessage(plaintext, ciphertext, cphr_size, iv, encrypted_key, encrypted_key_len, tprivk, plaintext_len)) { cerr<<"ERR: Error while decrypting"<<endl; exit(1); }

    return plaintext;
}

string SecureChatClient::receiveAvailableUsers(){
    char* enc_buf = (char*)malloc(AVAILABLE_USER_MAX_SIZE+ENC_FIELDS);
    if (!enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)enc_buf, AVAILABLE_USER_MAX_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the message containing the list of users"<<endl; exit(1); }

    cout<<"Len: "<<len<<endl;

    cout<<"LOG: Message containing the list of users received"<<endl;

    unsigned char* buf = (unsigned char*)malloc(AVAILABLE_USER_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)enc_buf);
    if (Utility::decryptSessionMessage(buf, (unsigned char*)enc_buf, len, this->K, buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };
    
    unsigned int message_type = buf[0];
    if (message_type != 2){ cerr<<"ERR: The message type is not corresponding to 'user list'"<<endl; exit(1); }

    unsigned int user_number = buf[1];
    unsigned int current_len = 2;
    unsigned int username_len;
    char current_username[USERNAME_MAX_SIZE];

    /* ------------------------------------------------------------------------------------------------------------------------------- *\
    |* 2 | number of available user(1)| username len(1) | username(MAX=16) | ... | username_len(1) | username(MAX=16) | signature(256) *|
    \* ------------------------------------------------------------------------------------------------------------------------------- */
    map<unsigned int, string> users_online;
    if (user_number < 0){ cerr<<"ERR: The number of available users is negative."<<endl; exit(1); }
    if (user_number == 0){ 
        cout<<"LOG: There are no available users."<<endl; 
    } else {
        cout<<"LOG: Online Users"<<endl;
    }
    for (unsigned int i = 0; i < user_number; i++){
        if (current_len >= AVAILABLE_USER_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
        username_len = buf[current_len];
        if (username_len >= USERNAME_MAX_SIZE){ cerr<<"ERR: The username length is too long."<<endl; exit(1); }
        if (current_len+1 == 0){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
        current_len++;
        if (current_len + (unsigned long)buf < current_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
        memcpy(current_username, buf+current_len, username_len);
        current_username[username_len] = '\0';
        cout<<"    "<<i<<": "<<current_username<<endl;
        if (username_len + current_len < username_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
        current_len += username_len;
        users_online.insert(pair<unsigned int, string>(i, (string)current_username));
    }
    cout<<"    q: Logout"<<endl;

    string selected;
    cout<<"LOG: Select an option or the number corresponding to one of the users: ";
    cin>>selected;
    if(!cin) {exit(1);}

    while((!Utility::isNumeric(selected) || atoi(selected.c_str()) >= user_number) && selected.compare("q") != 0){
        cerr<<"ERR: Selection is not valid! Select another option or number: ";
        cin>>selected;
        if(!cin) {exit(1);}
    }

    if (selected.compare("q") == 0){
        logout(1);
        exit(0);
    }

    return users_online.at(atoi(selected.c_str()));
}

void SecureChatClient::sendRTT(string selected_user){
    /* ------------------------------------------------------------------------- *\
    |* 3 | receiver_username_len(1) | receiver_username(MAX=16) | signature(256) *|
    \* ------------------------------------------------------------------------- */
    char msg[RTT_MAX_SIZE];
    msg[0] = 3; 
    char receiver_username_len = selected_user.length();
    msg[1] = receiver_username_len;
    if (receiver_username_len + 2 < receiver_username_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int len = receiver_username_len + 2;
    if (len >= RTT_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    if (2 + (unsigned long)msg < 2){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy((msg+2), selected_user.c_str(), receiver_username_len);

    /* ---------------------------------------------------------- *\
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(1);
    unsigned char* ciphertext, *tag, *enc_buf;
    int outlen;
    unsigned int cipherlen;
    unsigned int enc_buf_max_len = 2 + receiver_username_len + ENC_FIELDS;
    unsigned int enc_buf_len;
    enc_buf = (unsigned char*)malloc(enc_buf_max_len);
    if (Utility::encryptSessionMessage(len, this->K, (unsigned char*)msg, ciphertext, outlen, cipherlen, this->user_counter, tag, enc_buf, enc_buf_max_len, 0, enc_buf_len) == false){
        cerr<<"Thread "<<gettid()<<"Error in the encryption"<<endl;
        pthread_exit(NULL);
    };
    
    if (send(this->server_socket, enc_buf, enc_buf_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the authentication message."<<endl; exit(1); }
};

string SecureChatClient::waitForRTT(){
    /* ------------------------------------------------------------------------- *\
    |* 3 | receiver_username_len(1) | receiver_username(MAX=16) | signature(256) *|
    \* ------------------------------------------------------------------------- */
    char* enc_buf = (char*)malloc(RTT_MAX_SIZE+ENC_FIELDS);
    if (!enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)enc_buf, RTT_MAX_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }

    unsigned char* buf = (unsigned char*)malloc(RTT_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)enc_buf);
    if (Utility::decryptSessionMessage(buf, (unsigned char*)enc_buf, len, this->K, buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };

    unsigned int message_type = buf[0];
    if (message_type != 3){ cerr<<"ERR: Message type is not corresponding to 'RTT type'."<<endl; exit(1); }
    unsigned int sender_username_len = buf[1];
    if (sender_username_len > USERNAME_MAX_SIZE){ cerr<<"ERR: Receiver Username length is over the upper bound."<<endl; }
    string sender_username;
    if ((unsigned long)buf + 2 < 2){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    sender_username.append((char*)buf+2, sender_username_len);

    return sender_username;
};

void SecureChatClient::sendResponse(string sender_username, unsigned int response){
    /* -------------------------------------------------------------------- *\
    |* 4 | response(1) | username_len(1) | username(MAX=16) | digest(256)   *|
    \* -------------------------------------------------------------------- */
    char msg[RESPONSE_MAX_SIZE];
    msg[0] = 4; 
    msg[1] = response;

    unsigned int username_len = sender_username.length();
    msg[2] = username_len;

    if (3 + username_len < 3){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int len = 3 + username_len;
    if (len > RESPONSE_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    if (3 + (unsigned long)msg < 3){ cerr<<"ERR: Wrap around"<<endl; exit(1); }

    memcpy(msg+3, sender_username.c_str(), username_len);

    /* ---------------------------------------------------------- *\
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(1);
    unsigned char* ciphertext, *tag, *enc_buf;
    int outlen;
    unsigned int cipherlen;
    unsigned int enc_buf_max_len = 2 + username_len + ENC_FIELDS;
    unsigned int enc_buf_len;
    enc_buf = (unsigned char*)malloc(enc_buf_max_len);
    if (Utility::encryptSessionMessage(len, this->K, (unsigned char*)msg, ciphertext, outlen, cipherlen, this->user_counter, tag, enc_buf, enc_buf_max_len, 0, enc_buf_len) == false){
        cerr<<"Thread "<<gettid()<<"Error in the encryption"<<endl;
        pthread_exit(NULL);
    };
    
    if (send(this->server_socket, enc_buf, enc_buf_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the authentication message."<<endl; exit(1); }

    cout<<"LOG: Sending Response to RTT equal to "<<response<<endl;
};

unsigned int SecureChatClient::waitForResponse(){
    /* -------------------------------------------------------------------- *\
    |* 4 | response(1) | username_len(1) | username(MAX=16) | digest(256)   *|
    \* -------------------------------------------------------------------- */
    char* enc_buf = (char*)malloc(RESPONSE_MAX_SIZE+ENC_FIELDS);
    if (!enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)enc_buf, RESPONSE_MAX_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }

    unsigned char* buf = (unsigned char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)enc_buf);
    if (Utility::decryptSessionMessage(buf, (unsigned char*)enc_buf, len, this->K, buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };
    cout<<"LOG: Response to RTT received!"<<endl;

    unsigned int message_type = buf[0];
    if (message_type != 4){ cerr<<"ERR: Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl; exit(1); }

    unsigned int response = buf[1];
    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    string sender_username;
    sender_username.append((char*)buf+3, username_len);

    cout<<"LOG: Received Response to RTT equal to "<<response<<endl;

    return response;
};

void SecureChatClient::logout(unsigned int authenticated){ 
    /* -------------------------------------------------------------------- *\
    |* 8 | 0/1 | signature(256) []: only whether user is authenticated      *|
    \* -------------------------------------------------------------------- */
    char msg[LOGOUT_MAX_SIZE];
    msg[0] = 8; 
    msg[1] = authenticated;
    unsigned int len = 2;
    unsigned int msg_len = 2;
    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(msg+len, this->logout_nonce, NONCE_SIZE);
    len += NONCE_SIZE;
    if(authenticated == 1){
        unsigned char* signature;
        unsigned int signature_len;
        Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

        if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
        if (len + signature_len < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
        msg_len = len + signature_len;
        if (msg_len > LOGOUT_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
        memcpy(msg+len, signature, signature_len);
    }
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"ERR: Error in the sendto of the logout message."<<endl;
		exit(1);
	}
    
    close(this->server_socket);
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function handles the sender role in the key           *|
|* establishment protocol.                                    *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatClient::senderKeyEstablishment(string receiver_username, EVP_PKEY* peer_key){

    /* ---------------------------------------------------------- *\    
    |* *************************   M1   ************************* *|
    |* 6 | R(16) | sender_signature (256)                         *|
    \* ---------------------------------------------------------- */

    /* ---------------------------------------------------------- *\
    |* Create message R                                           *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    unsigned char R[R_SIZE];
    RAND_bytes(R, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Insert R into the message M1                               *|
    \* ---------------------------------------------------------- */
    char m1[M1_SIZE];
    m1[0] = 6;
    Utility::secure_memcpy((unsigned char*)m1, 1, M1_SIZE, R, 0, R_SIZE, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(1);
    unsigned char* ciphertext, *tag, *enc_buf;
    int outlen;
    unsigned int cipherlen;
    unsigned int enc_buf_max_len = M1_SIZE + ENC_FIELDS;
    unsigned int enc_buf_len;
    enc_buf = (unsigned char*)malloc(enc_buf_max_len);
    if (Utility::encryptSessionMessage(M1_SIZE, this->K, (unsigned char*)m1, ciphertext, outlen, cipherlen, this->user_counter, tag, enc_buf, enc_buf_max_len, 1, enc_buf_len) == false){
        cerr<<"ERR: Error in the encryption"<<endl;
        exit(1);
    };

    Utility::printMessage("M1 cifrato: ", (unsigned char*)enc_buf, enc_buf_len);
    
    if (send(this->server_socket, enc_buf, enc_buf_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the M1 message."<<endl; exit(1); }


    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    |* 6 | R(16) | tpubkey(451) | sender_signature (256)          *|
    \* ---------------------------------------------------------- *

    /* ---------------------------------------------------------- *\
    |* Receiving M2 message from the receiver                     *|
    \* ---------------------------------------------------------- */
    char* m2_enc_buf = (char*)malloc(M2_SIZE+ENC_FIELDS);
    if (!m2_enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)m2_enc_buf, M2_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }

    unsigned char* m2 = (unsigned char*)malloc(M2_SIZE);
    if (!m2){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int m2_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)m2_enc_buf);
    if (Utility::decryptSessionMessage(m2, (unsigned char*)m2_enc_buf, len, this->K, m2_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };


    /* ---------------------------------------------------------- *\
    |* Verify message authenticity                                *|
    \* ---------------------------------------------------------- */
    if(m2_len < (SIGNATURE_SIZE+R_SIZE)) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = m2_len - SIGNATURE_SIZE - R_SIZE;
    if ((unsigned long)m2 + clear_message_len < (unsigned long)m2) { cerr<<"ERR: Wrap around"<<endl; exit(1); }

    if(Utility::verifyMessage(peer_key, (char*)m2, clear_message_len, (unsigned char*)((unsigned long)m2+clear_message_len+R_SIZE), SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error while receiving message m2"<<endl; exit(1);
    }

    /* ---------------------------------------------------------- *\
    |* Check if the two Rs are equal                              *|
    \* ---------------------------------------------------------- */
    unsigned char R_received[R_SIZE];
    if (1 + (unsigned long)m2 < 1) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(R_received, m2+1, R_SIZE);
    if (!Utility::compareR(R, R_received)){ exit(1); }

    /* ---------------------------------------------------------- *\
    |* Key session generation                                     *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    unsigned char K[K_SIZE];
    RAND_bytes(K, K_SIZE);

    /* ---------------------------------------------------------- *\
    |* Insert TpubK in a buffer for the BIO_write                 *|
    \* ---------------------------------------------------------- */
    if (1 + R_SIZE < 1) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int message_len = 1  + R_SIZE;
    long pubkey_len;
    Utility::secure_memcpy((unsigned char*)&pubkey_len, 0, sizeof(long), m2, message_len, M2_SIZE, sizeof(long));
    message_len += sizeof(long);
    unsigned char* tpubk_received = (unsigned char*)malloc(pubkey_len);
    if (!tpubk_received) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    Utility::secure_memcpy(tpubk_received, 0, pubkey_len, m2, message_len, M2_SIZE, pubkey_len);
    message_len += pubkey_len;

    /* ---------------------------------------------------------- *\
    |* Read the TpubK                                             *|
    \* ---------------------------------------------------------- */
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, tpubk_received, PUBKEY_MSG_SIZE);
    EVP_PKEY* tpubk = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    Utility::printPublicKey(tpubk);

    unsigned char r2[R_SIZE];
    Utility::secure_memcpy(r2, 0, R_SIZE, m2, message_len, M2_SIZE, R_SIZE);
    Utility::printMessage("R2 received: ", r2, R_SIZE);


    /* ------------------------------------------------------------------------------------ *\
    |* **********************************   M3   ****************************************** *|
    |* 6 | R(16) | E(tpubk, K)(16) | IV(16) | encrypted_key(384) | sender_signature (256)   *|
    \* ------------------------------------------------------------------------------------ */


    /* ---------------------------------------------------------- *\
    |* Encrypt K using TpubK                                      *|
    \* ---------------------------------------------------------- */
    char* buf = (char*)malloc(M3_SIZE);
    buf[0] = 6;
    Utility::secure_thread_memcpy((unsigned char*)buf, 1, M3_SIZE, r2, 0, R_SIZE, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Encrypt K using TpubK                                      *|
    \* ---------------------------------------------------------- */
    len = 1+R_SIZE;
    unsigned char plaintext[K_SIZE];
    unsigned char* encrypted_key, *m3_ciphertext;
    unsigned int m3_cipherlen;
    int m3_outlen, encrypted_key_len;
    Utility::secure_thread_memcpy(plaintext, 0, K_SIZE, K, 0, K_SIZE, K_SIZE);

    unsigned char* iv;
    if (!Utility::encryptMessage(K_SIZE, tpubk, plaintext, m3_ciphertext, encrypted_key, iv, encrypted_key_len, m3_outlen, m3_cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; pthread_exit(NULL); }
    Utility::secure_thread_memcpy((unsigned char*)buf, len, M3_SIZE, m3_ciphertext, 0, K_SIZE+16, m3_cipherlen);
    len += m3_cipherlen;
    Utility::secure_thread_memcpy((unsigned char*)buf, len, M3_SIZE, iv, 0, BLOCK_SIZE, BLOCK_SIZE);
    len += BLOCK_SIZE;
    Utility::secure_thread_memcpy((unsigned char*)buf, len, M3_SIZE, encrypted_key, 0, EVP_PKEY_size(tpubk), encrypted_key_len);
    len += encrypted_key_len;

    /* ---------------------------------------------------------- *\
    |* Sign the R2                                                *|
    \* ---------------------------------------------------------- */
    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(this->client_prvkey, (char*)r2, R_SIZE, &signature, &signature_len);
    Utility::secure_thread_memcpy((unsigned char*)buf, len, S3_SIZE, signature, 0, SIGNATURE_SIZE, signature_len);
    len += SIGNATURE_SIZE;

    /* ---------------------------------------------------------- *\
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(1);
    unsigned char* server_ciphertext, *server_tag, *server_enc_buf;
    int server_outlen;
    unsigned int server_cipherlen;
    unsigned int server_enc_buf_max_len = M3_SIZE + ENC_FIELDS;
    unsigned int server_enc_buf_len;
    server_enc_buf = (unsigned char*)malloc(server_enc_buf_max_len);
    if (Utility::encryptSessionMessage(len, this->K, (unsigned char*)buf, server_ciphertext, server_outlen, server_cipherlen, this->user_counter, server_tag, server_enc_buf, server_enc_buf_max_len, 1, server_enc_buf_len) == false){
        cerr<<"ERR: Error in the encryption"<<endl;
        exit(1);
    };

    Utility::printMessage("M3 cifrato: ", (unsigned char*)server_enc_buf, server_enc_buf_len);
    
    if (send(this->server_socket, server_enc_buf, server_enc_buf_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the M1 message."<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Delete TpubK                                               *|
    \* ---------------------------------------------------------- */
    EVP_PKEY_free(tpubk);

    chat(receiver_username, K, peer_key);

}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function handles the receiver role in the key         *|
|* establishment protocol.                                    *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatClient::receiverKeyEstablishment(string sender_username, EVP_PKEY* peer_key){

    /* ---------------------------------------------------------- *\
    |* *************************   M1   ************************* *|
    \* ---------------------------------------------------------- */


    cout<<"LOG: Receiver key establishment"<<endl;

    /* ---------------------------------------------------------- *\
    |* Receiving message M1 from the sender                       *|
    \* ---------------------------------------------------------- */
    char* enc_buf = (char*)malloc(M1_SIZE+ENC_FIELDS);
    if (!enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)enc_buf, M1_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }
    Utility::printMessage("M1 cifrato: ", (unsigned char*)enc_buf, len);

    cout<<"LOG: M1 received"<<endl;

    unsigned char* m1 = (unsigned char*)malloc(M1_SIZE);
    if (!m1){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)enc_buf);
    if (Utility::decryptSessionMessage(m1, (unsigned char*)enc_buf, len, this->K, buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };
    
    Utility::printMessage("M1:", m1, len);
    if(m1[0] != 6){ cerr<<"ERR: Received a message type different from 'key esablishment' type"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* creating a buffer containing random nonce R received       *|
    |* from sender_username                                       *|
    \* ---------------------------------------------------------- */
    unsigned char r[R_SIZE];
    memcpy(r, m1+1, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Generating TpubK e TprvK                                   *|
    \* ---------------------------------------------------------- */
    EVP_PKEY* tprivk = Utility::generateTprivK(this->username);
    EVP_PKEY* tpubk = Utility::generateTpubK(this->username);
    Utility::removeTprivK(this->username);
    Utility::removeTpubK(this->username);

    Utility::printPublicKey(tpubk);


    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    \* ---------------------------------------------------------- */

    /* ---------------------------------------------------------- *\
    |* Create message R_user                                      *|
    \* ---------------------------------------------------------- */
    unsigned char r2[R_SIZE];
    RAND_poll();
    RAND_bytes(r2, R_SIZE);
    Utility::printMessage("R2 sent: ", r2, R_SIZE);

    /* ------------------------------------------------------------------------------- *\
    |*0/1| nonce_server(16) | nonce_user(16) | tpubk(451) | username_len(1) | username(MAX=16) | signature(256)*|
    \* ------------------------------------------------------------------------------- */
    char msg[M2_SIZE];
    /* ---------------------------------------------------------- *\
    |* Type = choice(0,1), authentication message with 0          *|
    |* to send message or 1 to receive message                    *|
    \* ---------------------------------------------------------- */
    msg[0] = 6; 
    len = 1;
    Utility::secure_memcpy((unsigned char*)msg, len, M2_SIZE, r, 0, R_SIZE, R_SIZE);
    len += R_SIZE;

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, tpubk);
    char* pubkey_buf = NULL;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    Utility::secure_memcpy((unsigned char*)msg, len, M2_SIZE, (unsigned char*)&pubkey_size, 0, sizeof(long), sizeof(long));
    len += sizeof(long);
    Utility::secure_memcpy((unsigned char*)msg, len, M2_SIZE, (unsigned char*)pubkey_buf, 0, pubkey_size, pubkey_size);
    BIO_free(mbio);
    len += pubkey_size;

    unsigned int to_sign_len = len;
    Utility::secure_memcpy((unsigned char*)msg, len, M2_SIZE, r2, 0, R_SIZE, R_SIZE);
    len += R_SIZE;

    unsigned char* signature;
    unsigned int signature_len;

    Utility::signMessage(client_prvkey, msg, to_sign_len, &signature, &signature_len);
    Utility::secure_memcpy((unsigned char*)msg, len, M2_SIZE, (unsigned char*)signature, 0, SIGNATURE_SIZE, signature_len);
    memcpy(msg + len, signature, signature_len);
    len += signature_len;

    /* ---------------------------------------------------------- *\
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(1);
    unsigned char* m2_ciphertext, *m2_tag, *m2_enc_buf;
    int m2_outlen;
    unsigned int m2_cipherlen;
    unsigned int m2_enc_buf_max_len = len + ENC_FIELDS;
    unsigned int m2_enc_buf_len;
    m2_enc_buf = (unsigned char*)malloc(m2_enc_buf_max_len);
    Utility::printMessage("this->user_counter", (unsigned char*)&this->user_counter, sizeof(__uint128_t));
    if (Utility::encryptSessionMessage(len, this->K, (unsigned char*)msg, m2_ciphertext, m2_outlen, m2_cipherlen, this->user_counter, m2_tag, m2_enc_buf, m2_enc_buf_max_len, 0, m2_enc_buf_len) == false){
        cerr<<"Thread "<<gettid()<<"Error in the encryption"<<endl;
        pthread_exit(NULL);
    };
    
    if (send(this->server_socket, m2_enc_buf, m2_enc_buf_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the M1 message."<<endl; exit(1); }

    //TODO: inserire il controllo sul tipo di messaggio ricevuto per ogni receive


    /* ---------------------------------------------------------- *\
    |* *************************   M3   ************************* *|
    \* ---------------------------------------------------------- */
    char* m3_enc_buf = (char*)malloc(M3_SIZE+ENC_FIELDS);
    if (!m3_enc_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    len = recv(this->server_socket, (void*)m3_enc_buf, M3_SIZE+ENC_FIELDS, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the RTT message"<<endl; exit(1); }
    Utility::printMessage("M1 cifrato: ", (unsigned char*)m3_enc_buf, len);

    cout<<"LOG: M1 received"<<endl;

    unsigned char* buf = (unsigned char*)malloc(M3_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int m3_buf_len;
    incrementCounter(0);
    checkCounter(0, (unsigned char*)m3_enc_buf);
    if (Utility::decryptSessionMessage(buf, (unsigned char*)m3_enc_buf, len, this->K, m3_buf_len, 1) == false){
        cerr<<"ERR: Error while decrypting"<<endl;
        exit(1);
    };
    len = m3_buf_len;

    if (buf[0] != 6){
        cerr<<"ERR: Message type is not corresponding to M3"<<endl;
        exit(1);
    }
    /* ---------------------------------------------------------- *\
    |* Verify the authenticity of the message                     *|
    \* ---------------------------------------------------------- */
    if ((unsigned long)buf + R_SIZE < R_SIZE){ cerr<<"Wrap around"<<endl; exit(1); }
    if (len < SIGNATURE_SIZE){ cerr<<"Access out-of-bound"<<endl; exit(1); }
    if ((unsigned long)buf + len < len){ cerr<<"Wrap around"<<endl; exit(1); }
    if(Utility::verifyMessage(peer_key, (char*)buf+1, R_SIZE, (unsigned char*)((unsigned long)buf+len-SIGNATURE_SIZE), SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error while receiving the M3 message"<<endl;
        exit(1);
    }

    unsigned char R2_received[R_SIZE];
    Utility::secure_memcpy(R2_received, 0, R_SIZE, (unsigned char*)buf, 1, M3_SIZE, R_SIZE);
    if (Utility::compareR(R2_received, r2) == false){
        cerr<<"ERR: R2 not corrisponding"<<endl;
        exit(1);
    }

    /* ---------------------------------------------------------- *\
    |* Initialize variables for decrypting                        *|
    \* ---------------------------------------------------------- */
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    unsigned int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned int encrypted_key_len = EVP_PKEY_size(tprivk);
    unsigned int cphr_size = 2*BLOCK_SIZE;
    unsigned int plaintext_len;
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    unsigned char* m3_iv = (unsigned char*)malloc(iv_len);
    unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
    unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
    if(!encrypted_key || !m3_iv || !ciphertext || !plaintext) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }    

    /* ---------------------------------------------------------- *\
    |* Insert the fields from S3 into the respective variables    *|
    \* ---------------------------------------------------------- */
    unsigned int index = 1+R_SIZE;
    Utility::secure_memcpy(ciphertext, 0, cphr_size, (unsigned char*)buf, index, M3_SIZE, cphr_size);
    index += cphr_size;
    Utility::secure_memcpy(m3_iv, 0, iv_len, (unsigned char*)buf, index, M3_SIZE, iv_len);
    index += iv_len;
    Utility::secure_memcpy(encrypted_key, 0, encrypted_key_len, (unsigned char*)buf, index, M3_SIZE, encrypted_key_len);

    /* ---------------------------------------------------------- *\
    |* Decrypt the message                                        *|
    \* ---------------------------------------------------------- */
    if (!Utility::decryptMessage(plaintext, ciphertext, cphr_size, m3_iv, encrypted_key, encrypted_key_len, tprivk, plaintext_len)) { cerr<<"ERR: Error while decrypting"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Analyze the content of the plaintext                       *|
    \* ---------------------------------------------------------- */
    unsigned char K[K_SIZE];
    memcpy(K, plaintext, K_SIZE);

    /* ---------------------------------------------------------- *\
    |* Delete TpubK e TprivK                                      *|
    \* ---------------------------------------------------------- */
    EVP_PKEY_free(tprivk);
    EVP_PKEY_free(tpubk);

    chat(sender_username, K, peer_key);
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function handles the chat between two users.          *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatClient::chat(string other_username, unsigned char* K, EVP_PKEY* peer_key){
    cout<<"LOG: Starting chat with "<<other_username<<"(press 'q' to logout)"<<endl;

    /* ---------------------------------------------------------- *\
    |* Create a fd_set structure to manage the server socket      *|
    |* and the stdin.                                             *|
    \* ---------------------------------------------------------- */
    fd_set master, copy;
    FD_ZERO(&master);

    FD_SET(this->server_socket, &master);
    FD_SET(STDIN_FILENO, &master);
    unsigned int my_nonce = 0;
    unsigned int other_nonce = 0;

    while(true){
        copy = master;

        int count = select(FD_SETSIZE, &copy, NULL, NULL, NULL);
        /* ---------------------------------------------------------- *\
        |* The client receive a message from the server on the socket *|
        \* ---------------------------------------------------------- */   
        if (FD_ISSET(this->server_socket, &copy)){
            char msg[GENERAL_MSG_SIZE];
            unsigned int len = recv(this->server_socket, (void*)msg, GENERAL_MSG_SIZE, 0);
            if (len == 0){ exit(0); }
            if (len < 0){ cerr<<"ERR: Error in receiving a message from another user"<<endl; exit(1); }
            if (msg[0] != 9) { cerr<<"ERR: Message type is not corresponding to chat message."<<endl; exit(1); }
            /* ---------------------------------------------------------- *\
            |* Verify message authenticity                                *|
            \* ---------------------------------------------------------- */
            if(len < SIGNATURE_SIZE) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
            unsigned int clear_message_len = len - SIGNATURE_SIZE;
            if ((unsigned long)msg+clear_message_len < clear_message_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
            if (Utility::verifyMessage(peer_key, (char*)msg, clear_message_len, (unsigned char*)((unsigned long)msg+clear_message_len), SIGNATURE_SIZE) != 1) { 
                cerr<<"ERR: Authentication error while receiving message"<<endl; exit(1);
            }

            /* ---------------------------------------------------------- *\
            |* Initialize variables for decrypting                        *|
            \* ---------------------------------------------------------- */
            const EVP_CIPHER* cipher = EVP_aes_128_cbc();
            if (clear_message_len < 1) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
            unsigned int cphr_size = clear_message_len - 1;
            unsigned int plaintext_len;
            unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
            unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
            if(!ciphertext || !plaintext) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); } 
            if (1 + (unsigned long)msg < 1) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
            memcpy(ciphertext, msg+1, cphr_size);
            
            /* ---------------------------------------------------------- *\
            |* Decrypt the message                                        *|
            \* ---------------------------------------------------------- */

            //if (!Utility::decryptSessionMessage(plaintext, ciphertext, cphr_size, K, plaintext_len)) { cerr<<"ERR: Error while decrypting"<<endl; exit(1); }

            /* ---------------------------------------------------------- *\
            |* Verify the freshness                                       *|
            \* ---------------------------------------------------------- */
            unsigned int received_nonce;
            memcpy(&received_nonce, plaintext, sizeof(received_nonce));
            if (other_nonce != received_nonce){
                cerr<<"ERR: Replay attack"<<endl;
                exit(1);
            }
            char* buf = (char*)plaintext+sizeof(other_nonce);
            buf[plaintext_len-sizeof(other_nonce)] = '\0';
            if(strcmp((char*)plaintext+sizeof(other_nonce), "q") != 0){
                Utility::printChatMessage(other_username, (char*)plaintext+sizeof(other_nonce), plaintext_len-sizeof(other_nonce));
            } else {
                cout<<"LOG: "<<other_username<<" logout and close the communication"<<endl;
                cout<<"LOG: Logout..."<<endl;
                close(this->server_socket);
                exit(0);
            }
            other_nonce++;
        }
        /* ---------------------------------------------------------- *\
        |* The client input a message in the stdin                    *|
        \* ---------------------------------------------------------- */    
        if (FD_ISSET(STDIN_FILENO, &copy)){
            char* input = (char*)malloc(INPUT_SIZE);
            unsigned char msg[GENERAL_MSG_SIZE];
            msg[0] = 9;
            if (fgets(input, INPUT_SIZE, stdin)==NULL){ cerr<<"ERR: Error while reading from stdin."<<endl; exit(1);}
            char* p = strchr(input, '\n');
            if (p){*p = '\0';}
            if (strcmp(input, "")==0){continue;}
            /* ---------------------------------------------------------- *\
            |* Encrypt msg using K                                        *|
            \* ---------------------------------------------------------- */
            unsigned int msg_len = 1;
            
            unsigned int plaintext_len = strlen(input)+sizeof(my_nonce);
            unsigned char* plaintext = (unsigned char*)malloc(plaintext_len);
            if (!plaintext){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
            memcpy(plaintext, &my_nonce, sizeof(my_nonce));
            if (sizeof(my_nonce) + (unsigned long)plaintext < sizeof(my_nonce)){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
            memcpy(plaintext+sizeof(my_nonce), input, strlen(input));

            unsigned char *ciphertext;
            unsigned int cipherlen;
            int outlen;
            //if (!Utility::encryptSessionMessage(plaintext_len, K, plaintext, ciphertext, outlen, cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; exit(1); }
            if (cipherlen > GENERAL_MSG_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
            if (1 + (unsigned long)msg < 1) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
            memcpy(msg+1, ciphertext, cipherlen);
            msg_len += cipherlen;

            /* ---------------------------------------------------------- *\
            |* Sign the message                                           *|
            \* ---------------------------------------------------------- */
            unsigned char* signature;
            unsigned int signature_len;
            Utility::signMessage(client_prvkey, (char*)msg, msg_len, &signature, &signature_len);
            if (msg_len + (unsigned long)msg < msg_len) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
            memcpy(msg+msg_len, signature, signature_len);
            if (msg_len + signature_len < msg_len) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
            msg_len += signature_len;
            if (send(this->server_socket, msg, msg_len, 0) < 0) { cerr<<"ERR: Error in the sendto of a message."<<endl; exit(1); }
            my_nonce++;

            if(strcmp(input, "q")==0){
                /* ---------------------------------------------------------- *\
                |* authenticated logout                                      *|
                \* ---------------------------------------------------------- */
                cout<<"LOG: Logout..."<<endl;
                logout(1); 
                exit(0);
            }
        }
    }
}

void SecureChatClient::setCounters(unsigned char* iv){
    Utility::secure_memcpy((unsigned char*)&this->server_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_memcpy((unsigned char*)&this->user_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_memcpy((unsigned char*)&this->base_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    memset((unsigned char*)(&this->server_counter)+12, 0, 4);
    memset((unsigned char*)(&this->user_counter)+12, 0, 4);
    memset((unsigned char*)(&this->base_counter)+12, 0, 4);
}

void SecureChatClient::incrementCounter(int counter){
    //counter = 0 -> server, counter = 1 -> user
    if (counter == 0){
        this->server_counter++;
        memset((unsigned char*)(&this->server_counter)+12, 0, 4);
        return;
    }
    if (counter == 1){
        this->user_counter++;
        memset((unsigned char*)(&this->user_counter)+12, 0, 4);
        return;
    }
    cerr<<"Bad call of the function increment counter"<<endl;
    exit(1);
}

void SecureChatClient::checkCounter(int counter, unsigned char* received_counter_msg){
    //counter = 0 -> server, counter = 1 -> user
    __uint128_t received_counter;
    Utility::secure_memcpy((unsigned char*)&received_counter, 0, sizeof(__uint128_t), received_counter_msg, 0, 12, 12);
    memset((unsigned char*)(&received_counter)+12, 0, 4);
    if (counter == 0){
        __uint128_t server_counter_12 = this->server_counter;
        memset((unsigned char*)(&server_counter_12)+12, 0, 4);
        Utility::printMessage("Actual counter: ", (unsigned char*)&server_counter_12, sizeof(__uint128_t));
        if (server_counter_12 != received_counter || received_counter == this->base_counter){ cerr<<"Bad received server counter"<<endl; exit(1); }
        return;
    }
    if (counter == 1){
        __uint128_t user_counter_12 = this->user_counter;
        memset((unsigned char*)(&user_counter_12)+12, 0, 4);
        Utility::printMessage("Actual counter: ", (unsigned char*)&user_counter_12, sizeof(__uint128_t));
        if (user_counter_12 != received_counter || received_counter == this->base_counter){ cerr<<"Bad received user counter"<<endl; exit(1); }
        return;
    }
    cerr<<"Bad call of the function check counter"<<endl;
    exit(1);
}

void SecureChatClient::storeK(unsigned char* K){
    this->K = (unsigned char*)malloc(K_SIZE);
    Utility::secure_memcpy(this->K, 0, K_SIZE, K, 0, K_SIZE, K_SIZE);
}

void SecureChatClient::setChatCounters(unsigned char* iv){
    Utility::secure_memcpy((unsigned char*)&this->chat_peer_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_memcpy((unsigned char*)&this->chat_my_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_memcpy((unsigned char*)&this->chat_base_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    memset((unsigned char*)(&this->chat_peer_counter)+12, 0, 4);
    memset((unsigned char*)(&this->chat_my_counter)+12, 0, 4);
    memset((unsigned char*)(&this->chat_base_counter)+12, 0, 4);
}

void SecureChatClient::incrementChatCounter(int counter){
    //counter = 0 -> chat_peer, counter = 1 -> user
    if (counter == 0){
        this->chat_peer_counter++;
        memset((unsigned char*)(&this->chat_peer_counter)+12, 0, 4);
        return;
    }
    if (counter == 1){
        this->chat_my_counter++;
        memset((unsigned char*)(&this->chat_my_counter)+12, 0, 4);
        return;
    }
    cerr<<"Bad call of the function increment counter"<<endl;
    exit(1);
}

void SecureChatClient::checkChatCounter(int counter, unsigned char* received_counter_msg){
    //counter = 0 -> chat_peer, counter = 1 -> user
    __uint128_t received_counter;
    Utility::secure_memcpy((unsigned char*)&received_counter, 0, sizeof(__uint128_t), received_counter_msg, 0, 12, 12);
    memset((unsigned char*)(&received_counter)+12, 0, 4);
    if (counter == 0){
        __uint128_t chat_peer_counter_12 = this->chat_peer_counter;
        memset((unsigned char*)(&chat_peer_counter_12)+12, 0, 4);
        Utility::printMessage("Correct counter: ", (unsigned char*)&chat_peer_counter_12, sizeof(__uint128_t));
        Utility::printMessage("Received counter: ", (unsigned char*)&received_counter, sizeof(__uint128_t));
        Utility::printMessage("chat_base counter: ", (unsigned char*)&this->chat_base_counter, sizeof(__uint128_t));
        if (chat_peer_counter_12 != received_counter || received_counter == this->chat_base_counter){ cerr<<"Bad received chat_peer counter"<<endl; exit(1); }
        return;
    }
    if (counter == 1){
        __uint128_t chat_my_counter_12 = this->chat_my_counter;
        memset((unsigned char*)(&chat_my_counter_12)+12, 0, 4);
        if (chat_my_counter_12 != received_counter || received_counter == this->chat_base_counter){ cerr<<"Bad received user counter"<<endl; exit(1); }
        return;
    }
    cerr<<"Bad call of the function check counter"<<endl;
    exit(1);
}

void SecureChatClient::storeChatK(unsigned char* K){
    this->chat_K = (unsigned char*)malloc(K_SIZE);
    Utility::secure_memcpy(this->chat_K, 0, K_SIZE, K, 0, K_SIZE, K_SIZE);
}