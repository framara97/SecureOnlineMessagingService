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
    |* Receive server certificate                                 *|
    \* ---------------------------------------------------------- */
    receiveCertificate();

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
    |* Create logout nonce                                        *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    RAND_bytes(this->logout_nonce, NONCE_SIZE);

    /* ---------------------------------------------------------- *\
    |* Send a message to authenticate to the server               *|
    \* ---------------------------------------------------------- */
    authenticateUser(choice);

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

void SecureChatClient::receiveCertificate(){
    unsigned char* certificate_buf = (unsigned char*)malloc(CERTIFICATE_MAX_SIZE);
    if (!certificate_buf){
        cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    cout<<"LOG: Waiting for certificate"<<endl;
    if (recv(this->server_socket, (void*)certificate_buf, CERTIFICATE_MAX_SIZE, 0) < 0){ cerr<<"ERR: Error in receiving the certificate"<<endl; exit(1); }
    cout<<"LOG: Certificate received"<<endl;

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, certificate_buf, CERTIFICATE_MAX_SIZE);
    this->server_certificate = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    BIO_free(mbio);
}

EVP_PKEY* SecureChatClient::receiveUserPubKey(string username){
    /* ---------------------------------------------------------- *\
    |* 5 | pubkey(451) | signature(256)                           *|
    \* ---------------------------------------------------------- */
    unsigned char* pubkey_buf = (unsigned char*)malloc(PUBKEY_MSG_SIZE);
    if (!pubkey_buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }

    cout<<"LOG: Waiting for public key"<<endl;
    unsigned int len = recv(this->server_socket, (void*)pubkey_buf, PUBKEY_MSG_SIZE, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the public key"<<endl; exit(1); }
    if (pubkey_buf[0] != 5){ cerr<<"ERR: Message type is not corresponding to 'pubkey type'."<<endl; exit(1); }
    cout<<"LOG: Public key received from "<<username<<endl;

    if (len < SIGNATURE_SIZE){ cerr<<"ERR: Wrap around"<<endl; exit(1); }

    unsigned int clear_message_len = len - SIGNATURE_SIZE;

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (clear_message_len + (unsigned long)pubkey_buf < clear_message_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(signature, pubkey_buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, pubkey_buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error in the receiveUserPubKey"<<endl;
        exit(1);
    }

    if (1 + (unsigned long)pubkey_buf < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (clear_message_len < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, pubkey_buf+1, clear_message_len-1);
    EVP_PKEY* peer_pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return peer_pubkey;
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

void SecureChatClient::authenticateUser(unsigned int choice){

    if (username.length() >= USERNAME_MAX_SIZE){ cerr<<"ERR: Username length too large."<<endl; exit(1); }
    
    const unsigned int plaintext_len = NONCE_SIZE;
    unsigned char plaintext[plaintext_len];
    unsigned char* encrypted_key, *iv, *ciphertext;
    unsigned int cipherlen;
    int outlen, encrypted_key_len;
    memcpy(plaintext, this->logout_nonce, NONCE_SIZE);

    if (!Utility::encryptMessage(plaintext_len, this->server_pubkey, plaintext, ciphertext, encrypted_key, iv, encrypted_key_len, outlen, cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; exit(1); }
    if (cipherlen > LOGOUT_NONCE_MSG_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }

    /* ------------------------------------------------------------------------------- *\
    |* 0/1| username_len(1) | username(MAX=16) | logout_nonce(16) | signature(256)     *|
    \* ------------------------------------------------------------------------------- */
    char msg[AUTHENTICATION_MAX_SIZE];
    /* ---------------------------------------------------------- *\
    |* Type = choice(0,1), authentication message with 0          *|
    |* to send message or 1 to receive message                    *|
    \* ---------------------------------------------------------- */
    msg[0] = choice; 
    unsigned int username_len = username.length(); 
    msg[1] = username_len;
    if (username_len + 2 < username_len){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    unsigned int len = username_len + 2;
    if (len >= AUTHENTICATION_MAX_SIZE-SIGNATURE_SIZE){ cerr<<"ERR: Message too long."<<endl; exit(1); }
    if (2 + (unsigned long)msg < 2){ cerr<<"ERR: Wrap around."<<endl; exit(1); }

    memcpy(msg+2, username.c_str(), username_len);

    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around."<<endl; exit(1); }

    memcpy(msg + len, ciphertext, cipherlen);
    len += cipherlen;
    
    unsigned int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + iv_len < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + iv_len > LOGOUT_NONCE_MSG_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(msg + len, iv, iv_len);
    len += iv_len;
    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + encrypted_key_len < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + encrypted_key_len > LOGOUT_NONCE_MSG_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(msg + len, encrypted_key, encrypted_key_len);
    len += encrypted_key_len;

    unsigned char* signature;
    unsigned int signature_len;
    if (len + signature_len < len){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);
    if (len + signature_len >= AUTHENTICATION_MAX_SIZE){ cerr<<"ERR: Message too long."<<endl; exit(1); }
    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    memcpy(msg + len, signature, signature_len);
    len += signature_len;
    
    if (send(this->server_socket, msg, len, 0) < 0){
		cerr<<"ERR: Error in the sendto of the authentication message."<<endl;
		exit(1);
	}
}

string SecureChatClient::receiveAvailableUsers(){
    char* buf = (char*)malloc(AVAILABLE_USER_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)buf, AVAILABLE_USER_MAX_SIZE, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving the message containing the list of users"<<endl; exit(1); }

    cout<<"LOG: Message containing the list of users received"<<endl;

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (len < SIGNATURE_SIZE){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"ERR: Wrap around."<<endl; exit(1); }

    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);
    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error in the receiveAvailableUsers"<<endl;
        exit(1);
    }

    if (clear_message_len < 2){ cerr<<"ERR: Message format is not correct"<<endl; exit(1); }
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

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + signature_len < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int msg_len = len + signature_len;
    if (msg_len >= RTT_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(msg+len, signature, signature_len);
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the authentication message."<<endl; exit(1); }
};

string SecureChatClient::waitForRTT(){
    /* ------------------------------------------------------------------------- *\
    |* 3 | receiver_username_len(1) | receiver_username(MAX=16) | signature(256) *|
    \* ------------------------------------------------------------------------- */
    char* buf = (char*)malloc(RTT_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }

    cout<<"LOG: Waiting for RTT..."<<endl;
    unsigned int len = recv(this->server_socket, (void*)buf, RTT_MAX_SIZE, 0);
    cout<<len<<endl;
    if (len < 0){ cerr<<"ERR: Error in receiving a RTT from another user"<<endl; exit(1); }
    cout<<"LOG: RTT received!"<<endl;

    unsigned int message_type = buf[0];
    if (message_type != 3){ cerr<<"ERR: Message type is not corresponding to 'RTT type'."<<endl; exit(1); }
    unsigned int sender_username_len = buf[1];
    if (sender_username_len > USERNAME_MAX_SIZE){ cerr<<"ERR: Receiver Username length is over the upper bound."<<endl; }
    string sender_username;
    if (sender_username_len + 2 < sender_username_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = sender_username_len + 2;
    if (clear_message_len >= RTT_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    sender_username.append(buf+2, sender_username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) {  cerr<<"ERR: Authentication error in the waitForRTT"<<endl; exit(1); }

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

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (len + signature_len < len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int msg_len = len + signature_len;
    if (msg_len > RESPONSE_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(msg + len, signature, signature_len);
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){ cerr<<"ERR: Error in the sendto of the Response to RTT message."<<endl; exit(1); }

    cout<<"LOG: Sending Response to RTT equal to "<<response<<endl;
};

unsigned int SecureChatClient::waitForResponse(){
    /* -------------------------------------------------------------------- *\
    |* 4 | response(1) | username_len(1) | username(MAX=16) | digest(256)   *|
    \* -------------------------------------------------------------------- */
    char* buf = (char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }

    cout<<"LOG: Waiting for Response to RTT..."<<endl;
    unsigned int len = recv(this->server_socket, (void*)buf, AVAILABLE_USER_MAX_SIZE, 0);

    if (len < 0){ cerr<<"ERR: Error in receiving a Response RTT from another user"<<endl; exit(1); }
    cout<<"LOG: Response to RTT received!"<<endl;

    unsigned int message_type = buf[0];
    if (message_type != 4){ cerr<<"ERR: Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl; exit(1); }

    unsigned int response = buf[1];
    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (3 + username_len < 3){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = 3 + username_len;
    if (clear_message_len > RESPONSE_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    string sender_username;
    sender_username.append(buf+3, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error in the waitForResponse"<<endl;
        exit(1);
    }

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
    if (1 + (unsigned long)m1 < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(m1+1, R, R_SIZE);
    unsigned int m1_len = R_SIZE + 1;

    /* ---------------------------------------------------------- *\
    |* Sign the M1 message                                        *|
    \* ---------------------------------------------------------- */
    unsigned char* m1_signature;
    unsigned int m1_signature_len;
    Utility::signMessage(client_prvkey, m1, m1_len, &m1_signature, &m1_signature_len);
    if (m1_len + (unsigned long)m1 < m1_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m1_len + m1_signature_len < m1_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m1_len + m1_signature_len > RESPONSE_MAX_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(m1+m1_len, m1_signature, m1_signature_len);
    m1_len = m1_len + m1_signature_len;

    /* ---------------------------------------------------------- *\
    |* Send the M1 message                                        *|
    \* ---------------------------------------------------------- */
    if (send(this->server_socket, m1, m1_len, 0) < 0) { cerr<<"ERR: Error in the sendto of the message R"<<endl; exit(1); }


    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Receiving M2 message from the receiver                     *|
    \* ---------------------------------------------------------- */
    char* m2 = (char*)malloc(M2_SIZE);
    if (!m2){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1);}
    unsigned int m2_len = recv(this->server_socket, (void*)m2, M2_SIZE, 0);
    if (m2_len < 0) { cerr<<"ERR: Error in receiving M2 from another user"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Verify message authenticity                                *|
    \* ---------------------------------------------------------- */
    if(m2_len < SIGNATURE_SIZE) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = m2_len - SIGNATURE_SIZE;
    if ((unsigned long)m2 + clear_message_len < (unsigned long)m2) { cerr<<"ERR: Wrap around"<<endl; exit(1); }

    if(Utility::verifyMessage(peer_key, m2, clear_message_len, (unsigned char*)((unsigned long)m2+clear_message_len), SIGNATURE_SIZE) != 1) { 
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
    unsigned int message_len = 1  + R_SIZE; //one byte for message type
    unsigned char* tpubk_received = (unsigned char*)malloc(PUBKEY_MSG_SIZE);
    if (!tpubk_received) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (message_len + (unsigned long)m2 < message_len) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(tpubk_received, m2+message_len, PUBKEY_MSG_SIZE);
    if (message_len + PUBKEY_MSG_SIZE < message_len) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    message_len += PUBKEY_MSG_SIZE;

    /* ---------------------------------------------------------- *\
    |* Read the TpubK                                             *|
    \* ---------------------------------------------------------- */
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, tpubk_received, PUBKEY_MSG_SIZE);
    EVP_PKEY* tpubk = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);


    /* ---------------------------------------------------------- *\
    |* *************************   M3   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Encrypt K using TpubK                                      *|
    \* ---------------------------------------------------------- */
    unsigned char m3[M3_SIZE];
    unsigned int m3_len = 0;
    const unsigned int plaintext_len = K_SIZE + 1;
    unsigned char plaintext[plaintext_len];
    plaintext[0] = 6;
    unsigned char* encrypted_key, *iv, *ciphertext;
    unsigned int cipherlen;
    int outlen, encrypted_key_len;
    if (1 + (unsigned long)plaintext < 1){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(plaintext+1, K, K_SIZE);

    if (!Utility::encryptMessage(plaintext_len, tpubk, plaintext, ciphertext, encrypted_key, iv, encrypted_key_len, outlen, cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; exit(1); }
    if (cipherlen > M3_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(m3, ciphertext, cipherlen);
    m3_len = cipherlen;
    unsigned int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    if (m3_len + (unsigned long)m3 < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + iv_len < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + iv_len > M3_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(m3+m3_len, iv, iv_len);
    m3_len += iv_len;
    if (m3_len + (unsigned long)m3 < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + encrypted_key_len < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + encrypted_key_len > M3_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(m3+m3_len, encrypted_key, encrypted_key_len);
    m3_len += encrypted_key_len;

    /* ---------------------------------------------------------- *\
    |* Sign the M3 message                                        *|
    \* ---------------------------------------------------------- */
    unsigned char* m3_signature;
    unsigned int m3_signature_len;
    Utility::signMessage(client_prvkey, (char*)m3, m3_len, &m3_signature, &m3_signature_len);
    if (m3_len + (unsigned long)m3 < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + m3_signature_len < m3_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    if (m3_len + m3_signature_len > M3_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    memcpy(m3+m3_len, m3_signature, m3_signature_len);
    m3_len += m3_signature_len;

    /* ---------------------------------------------------------- *\
    |* Send the M3 message                                        *|
    \* ---------------------------------------------------------- */
    if (send(this->server_socket, m3, m3_len, 0) < 0) { 
        cerr<<"ERR: Error in the sendto of the message M3"<<endl; 
        exit(1); 
    }

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
    char* m1 = (char*)malloc(M1_SIZE);
    if (!m1){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    unsigned int len = recv(this->server_socket, (void*)m1, M1_SIZE, 0);
    if(len < 0){ cerr<<"ERR: Error in receiving M1 from another user"<<endl; exit(1); }
    if(m1[0] != 6){ cerr<<"ERR: Received a message type different from 'key esablishment' type"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Verify message M1 authenticity                             *|
    \* ---------------------------------------------------------- */
    if(len < SIGNATURE_SIZE) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if (Utility::verifyMessage(peer_key, m1, clear_message_len, (unsigned char*)((unsigned long)m1+clear_message_len), SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error while receiving message m1"<<endl; exit(1);
    }

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


    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    \* ---------------------------------------------------------- */

    /* ---------------------------------------------------------- *\
    |* Send M2: <R || TpubKb>B                                    *|
    |* (we don't send the certificate because the other peer has  *|
    |* yet the public key)                                        *|
    \* ---------------------------------------------------------- */
    char m2[M2_SIZE];
    m2[0] = 6;

    /* ---------------------------------------------------------- *\
    |* Inserting R || TpubKb in the M2 message                    *|
    \* ---------------------------------------------------------- */
    if (1 + (unsigned long)m2 < 1) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(m2+1, r, R_SIZE);
    if (1 + R_SIZE < 1) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    len = 1 + R_SIZE;
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, tpubk);
    char* pubkey_buf = NULL;
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    if (1 + pubkey_size > PUBKEY_MSG_SIZE) { cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
    if (len + (unsigned long)m2 < len) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    memcpy(m2+len, pubkey_buf, pubkey_size);
    BIO_free(mbio);
    if (pubkey_size + len < pubkey_size){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    len += pubkey_size;

    /* ---------------------------------------------------------- *\
    |* Sign the M2 message                                        *|
    \* ---------------------------------------------------------- */
    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, m2, len, &signature, &signature_len);
    if (len + (unsigned long)m2 < len) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
    memcpy(m2+len, signature, signature_len);
    if (len + signature_len < len) { cerr<<"ERR: Wrap around."<<endl; exit(1); }
    len += signature_len;

    /* ---------------------------------------------------------- *\
    |* Send M2 message to the sender                              *|
    \* ---------------------------------------------------------- */
    if (send(this->server_socket, m2, len, 0) < 0) { cerr<<"ERR: Error in the sendto of the m2 message."<<endl; exit(1); }

    //TODO: inserire il controllo sul tipo di messaggio ricevuto per ogni receive


    /* ---------------------------------------------------------- *\
    |* *************************   M3   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Receive M3 message from the sender                         *|
    \* ---------------------------------------------------------- */
    unsigned char m3[M3_SIZE];
    len = recv(this->server_socket, (void*)m3, M3_SIZE, 0);
    if (len < 0){ cerr<<"ERR: Error in receiving message M3 from another user"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Verify message M3 authenticity                             *|
    \* ---------------------------------------------------------- */
    if(len < SIGNATURE_SIZE) { cerr<<"ERR: Wrap around"<<endl; exit(1); }
    clear_message_len = len - SIGNATURE_SIZE;
    if (Utility::verifyMessage(peer_key, (char*)m3, clear_message_len, (unsigned char*)((unsigned long)m3+clear_message_len), SIGNATURE_SIZE) != 1) { 
        cerr<<"ERR: Authentication error while receiving message M3"<<endl; exit(1);
    }

    /* ---------------------------------------------------------- *\
    |* Initialize variables for decrypting                        *|
    \* ---------------------------------------------------------- */
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    unsigned int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned int encrypted_key_len = EVP_PKEY_size(tprivk);
    unsigned int cphr_size = clear_message_len - encrypted_key_len - iv_len;
    unsigned int plaintext_len;
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
    unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
    if(!encrypted_key || !iv || !ciphertext || !plaintext) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }    

    /* ---------------------------------------------------------- *\
    |* Insert the fields from M3 into the respective variables    *|
    \* ---------------------------------------------------------- */
    unsigned int index = 0;
    memcpy(ciphertext, m3, cphr_size);
    index = cphr_size;
    if (index + (unsigned long)m3 < index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    memcpy(iv, m3+index, iv_len);
    if (index + iv_len < index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    index += iv_len;
    if (index + (unsigned long)m3 < index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    memcpy(encrypted_key, m3+index, encrypted_key_len);

    /* ---------------------------------------------------------- *\
    |* Decrypt the message                                        *|
    \* ---------------------------------------------------------- */
    if (!Utility::decryptMessage(plaintext, ciphertext, cphr_size, iv, encrypted_key, encrypted_key_len, tprivk, plaintext_len)) { cerr<<"ERR: Error while decrypting"<<endl; exit(1); }

    /* ---------------------------------------------------------- *\
    |* Analyze the content of the plaintext                       *|
    \* ---------------------------------------------------------- */
    if(plaintext[0] != 6){ cerr<<"ERR: Received a message type different from 'key esablishment' type"<<endl; exit(1); }
    unsigned char K[K_SIZE];
    memcpy(K, plaintext+1, K_SIZE);

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

        if (FD_ISSET(this->server_socket, &copy)){
            char msg[GENERAL_MSG_SIZE];
            unsigned int len = recv(this->server_socket, (void*)msg, GENERAL_MSG_SIZE, 0);
            if (len == 0){ exit(0); }
            if (len < 0){ cerr<<"ERR: Error in receiving a message from another user"<<endl; exit(1); }

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
            unsigned int cphr_size = clear_message_len;
            unsigned int plaintext_len;
            unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
            unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
            if(!ciphertext || !plaintext) { cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); } 
            memcpy(ciphertext, msg, cphr_size);
            
            /* ---------------------------------------------------------- *\
            |* Decrypt the message                                        *|
            \* ---------------------------------------------------------- */
            //cout<<"Plaintext len: "<<plaintext_len<<endl;
            if (!Utility::decryptSessionMessage(plaintext, ciphertext, cphr_size, K, plaintext_len)) { cerr<<"ERR: Error while decrypting"<<endl; exit(1); }
            //Utility::printMessage("Plaintext ricevuto:", plaintext, plaintext_len);

            /* ---------------------------------------------------------- *\
            |* Verify the freshness                                       *|
            \* ---------------------------------------------------------- */
            unsigned int received_nonce;
            memcpy(&received_nonce, plaintext, sizeof(received_nonce));
            // cout<<"Other nonce: "<<other_nonce<<endl;
            // cout<<"Received nonce: "<<received_nonce<<endl;
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
        if (FD_ISSET(STDIN_FILENO, &copy)){
            char* input = (char*)malloc(INPUT_SIZE);
            unsigned char msg[GENERAL_MSG_SIZE];
            if (fgets(input, INPUT_SIZE, stdin)==NULL){ cerr<<"ERR: Error while reading from stdin."<<endl; exit(1);}
            char* p = strchr(input, '\n');
            if (p){*p = '\0';}
            if (strcmp(input, "")==0){continue;}
            /* ---------------------------------------------------------- *\
            |* Encrypt msg using K                                        *|
            \* ---------------------------------------------------------- */
            unsigned int msg_len = 0;
            
            unsigned int plaintext_len = strlen(input)+sizeof(my_nonce);
            unsigned char* plaintext = (unsigned char*)malloc(plaintext_len);
            if (!plaintext){ cerr<<"ERR: There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
            memcpy(plaintext, &my_nonce, sizeof(my_nonce));
            if (sizeof(my_nonce) + (unsigned long)plaintext < sizeof(my_nonce)){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
            memcpy(plaintext+sizeof(my_nonce), input, strlen(input));

            unsigned char *ciphertext;
            unsigned int cipherlen;
            int outlen;
            if (!Utility::encryptSessionMessage(plaintext_len, K, plaintext, ciphertext, outlen, cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; exit(1); }
            if (cipherlen > GENERAL_MSG_SIZE){ cerr<<"ERR: Access out-of-bound"<<endl; exit(1); }
            memcpy(msg, ciphertext, cipherlen);
            msg_len = cipherlen;

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