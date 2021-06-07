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
EVP_PKEY* SecureChatClient::client_prvkey = NULL;
X509* SecureChatClient::ca_certificate = NULL;
X509* SecureChatClient::own_certificate = NULL;
X509_CRL* SecureChatClient::ca_crl = NULL;

SecureChatClient::SecureChatClient(string client_username, const char *server_addr, unsigned short int server_port) {
    if (client_username.length() > USERNAME_MAX_SIZE){
        cerr<<"Username too long."<<endl;
        exit(1);
    }

    if (strlen(server_addr) > MAX_ADDRESS_SIZE){
        cerr<<"Server address out of bound."<<endl;
    }

    //Set username
    username = client_username;

    //Read the client private key
    client_prvkey = getPrvKey();

    //Read the CA certificate
    ca_certificate = getCertificate();

    //Read the CRL
    ca_crl = getCRL();

    //Set the server address and the server port in the class instance
    strncpy(this->server_address, server_addr, MAX_ADDRESS_SIZE-1);
    this->server_address[MAX_ADDRESS_SIZE-1] = '\0';
    this->server_port = server_port;

    //Setup the server socket
    setupServerSocket(server_port, server_addr);

    //Receive server certificate
    receiveCertificate();

    //Verify server certificate
    verifyCertificate();

    string input;

    cout<<"Do you want to"<<endl<<"0: Send a message"<<endl<<"1: Receive a message"<<endl<<"q: Logout"<<endl;
    cout<<"Select a choice: ";
    cin>>input;
    if(!cin){exit(1);}
    while(1){
        if(input.compare("0")!=0 && input.compare("1")!=0 && input.compare("q")!=0){
            cout<<"Choice not valid! Choose 0, 1 or 2!"<<endl;
            cin>>input;
            if(!cin){exit(1);}
        } else break;
    }

    if(input.compare("q")==0){
        //Logout
        logout(0); //non-authenticated logout
        exit(0);
    }
    choice = input.c_str()[0]-'0';

    cout << "choice: " << choice << endl;

    //Send a message to authenticate to the server
    authenticateUser(choice);

    unsigned int response;
    EVP_PKEY* peer_key;

    if(choice == 0){ //client wants to send a message
        //Print the user list and select a user to communicate with 
        string selected_user = receiveAvailableUsers();

        //Send request to talk to the selected user
        sendRTT(selected_user);

        //Wait fot the answer to the previous RTT
        response = waitForResponse();

        if(response==1){

            //Wait for the selected_user public key
            peer_key = receiveUserPubKey(selected_user);

            //Handle key establishment
            senderKeyEstablishment(selected_user, peer_key);
        }
    } else if(choice == 1){ //client wants to receive a message
        string sender_username = waitForRTT();

        cout<<"Authentication is ok"<<endl;
        cout<<sender_username<<" wants to send you a message. Do you want to "<<endl<<"0: Refuse"<<endl<<"1: Accept"<<endl;
        cout<<"Select a choice: ";
        cin>>response;
        if(!cin){exit(1);}
        while(1){
            if(response != 0 && response != 1){
                cout<<"Choice not valid! Choose 0 or 1!"<<endl;
                cin>>response;
                if(!cin){exit(1);}
            } else break;
        }

        sendResponse(sender_username, response);

        if(response==1){

            //Wait for the selected_user public key
            peer_key = receiveUserPubKey(sender_username);

            //Handle key establishment
            receiverKeyEstablishment(sender_username, peer_key);
        }
    }
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

	if (connect(this->server_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Error in the connect"<<endl;
		exit(1);
	}
    cout<<"Connected to the server"<<endl;
}

void SecureChatClient::receiveCertificate(){
    unsigned char* certificate_buf = (unsigned char*)malloc(CERTIFICATE_MAX_SIZE);
    if (!certificate_buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    cout<<"Waiting for certificate"<<endl;
    if (recv(this->server_socket, (void*)certificate_buf, CERTIFICATE_MAX_SIZE, 0) < 0){
        cerr<<"Error in receiving the certificate"<<endl;
        exit(1);
    }
    cout<<"Certificate received"<<endl;

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, certificate_buf, CERTIFICATE_MAX_SIZE);
    this->server_certificate = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    BIO_free(mbio);
}

EVP_PKEY* SecureChatClient::receiveUserPubKey(string username){
    // 5 | pubkey | signature
    unsigned char* pubkey_buf = (unsigned char*)malloc(PUBKEY_MSG_SIZE);
    if (!pubkey_buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    cout<<"Waiting for public key"<<endl;
    unsigned int len = recv(this->server_socket, (void*)pubkey_buf, PUBKEY_MSG_SIZE, 0);
    if (len < 0){
        cerr<<"Error in receiving the public key"<<endl;
        exit(1);
    }
    if (pubkey_buf[0] != 5){
        cerr<<"Message type is not corresponding to 'pubkey type'."<<endl;
        exit(1);
    }
    cout<<"Public key received from "<<username<<endl;

    if (len < SIGNATURE_SIZE){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }

    unsigned int clear_message_len = len - SIGNATURE_SIZE;

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    if (clear_message_len + (unsigned long)pubkey_buf < clear_message_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy(signature, pubkey_buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    memcpy(clear_message, pubkey_buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error"<<endl;
        exit(1);
    }

    if (1 + (unsigned long)pubkey_buf < 1){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, pubkey_buf+1, PUBKEY_SIZE);
    EVP_PKEY* peer_pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return peer_pubkey;
}

void SecureChatClient::verifyCertificate(){
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_certificate);
    X509_STORE_add_crl(store, ca_crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, this->server_certificate, NULL);
    if(X509_verify_cert(ctx) != 1) { 
        cerr<<"The certificate of the server is not valid"<<endl;
        exit(1);
    }
    cout<<"The certificate of the server is valid"<<endl;

    this->server_pubkey = X509_get_pubkey(this->server_certificate);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

void SecureChatClient::authenticateUser(unsigned int choice){

    if (username.length() >= USERNAME_MAX_SIZE){
        cerr<<"Username length too large."<<endl;
        exit(1);
    }

    //Message choice(0,1)|len|"simeon"|prvk_simeon(digest)
    char msg[AUTHENTICATION_MAX_SIZE];
    msg[0] = choice; //Type = choice(0,1), authentication message with 0 to send message or 1 to receive message
    unsigned int username_len = username.length(); //if username length is less than 16, it can stay on one byte
    msg[1] = username_len;
    if (username_len + 2 < username_len){
        cerr<<"Wrap around."<<endl;
        exit(1);
    }
    unsigned int len = username_len + 2;
    if (len >= AUTHENTICATION_MAX_SIZE-SIGNATURE_SIZE){
        cerr<<"Message too long."<<endl;
        exit(1);
    }
    if (2 + (unsigned long)msg < 2){
        cerr<<"Wrap around."<<endl;
        exit(1);
    }
    memcpy(msg+2, username.c_str(), username_len);

    unsigned char* signature;
    unsigned int signature_len;
    if (len + signature_len < len){
        cerr<<"Wrap around."<<endl;
        exit(1);
    }
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);
    if (len + signature_len >= AUTHENTICATION_MAX_SIZE){
        cerr<<"Message too long."<<endl;
        exit(1);
    }
    if (len + (unsigned long)msg < len){
        cerr<<"Wrap around."<<endl;
        exit(1);
    }
    memcpy(msg+len, signature, signature_len);
    unsigned int msg_len = len + signature_len;
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"Error in the sendto of the authentication message."<<endl;
		exit(1);
	}
}

string SecureChatClient::receiveAvailableUsers(){
    char* buf = (char*)malloc(AVAILABLE_USER_MAX_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    unsigned int len = recv(this->server_socket, (void*)buf, AVAILABLE_USER_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Error in receiving the message containing the list of users"<<endl;
        exit(1);
    }

    cout<<"Message containing the list of users received"<<endl;

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    if (len < SIGNATURE_SIZE){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if (clear_message_len + (unsigned long)buf < clear_message_len){
        cerr<<"Wrap around."<<endl;
        exit(1);
    }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);
    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error"<<endl;
        exit(1);
    }
    cout<<"Authentication is ok"<<endl;

    if (clear_message_len < 2){
        cerr<<"Message format is not correct"<<endl;
        exit(1);
    }
    unsigned int message_type = buf[0];
    if (message_type != 2){
        cerr<<"The message type is not corresponding to 'user list'"<<endl;
        exit(1);
    }

    unsigned int user_number = buf[1];
    unsigned int current_len = 2;
    unsigned int username_len;
    char current_username[USERNAME_MAX_SIZE];
    // 2 | 2 | 6 | simeon | 5 | mbala
    map<unsigned int, string> users_online;
    if (user_number < 0){
        cerr<<"The number of available users is negative."<<endl;
        exit(1);
    }
    if (user_number == 0){
        cout<<"There are no available users."<<endl;
    }
    else{
        cout<<"Online Users"<<endl;
    }
    for (unsigned int i = 0; i < user_number; i++){
        if (current_len >= AVAILABLE_USER_MAX_SIZE){
            cerr<<"Access out-of-bound"<<endl;
            exit(1);
        }
        username_len = buf[current_len];
        if (username_len >= USERNAME_MAX_SIZE){
            cerr<<"The username length is too long."<<endl;
            exit(1);
        }
        if (current_len+1 == 0){
            cerr<<"Wrap around"<<endl;
            exit(1);
        }
        current_len++;
        if (current_len + (unsigned long)buf < current_len){
            cerr<<"Wrap around"<<endl;
            exit(1);
        }
        memcpy(current_username, buf+current_len, username_len);
        current_username[username_len] = '\0';
        cout<<i<<": "<<current_username<<endl;
        if (username_len + current_len < username_len){
            cerr<<"Wrap around"<<endl;
            exit(1);
        }
        current_len += username_len;
        users_online.insert(pair<unsigned int, string>(i, (string)current_username));
    }
    cout<<"q: Logout"<<endl;

    string selected;
    cout<<"Select an option or the number corresponding to one of the users: ";
    cin>>selected;
    if(!cin) {exit(1);}

    while((!Utility::isNumeric(selected) || atoi(selected.c_str()) >= user_number) && selected.compare("q") != 0){
        cout<<"Selection is not valid! Select another option or number: ";
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
    // 3 | receiver_username_len | receiver_username | signature
    char msg[RTT_MAX_SIZE];
    msg[0] = 3; //Type = 3, request to talk message
    char receiver_username_len = selected_user.length(); //receiver_username length on one byte
    msg[1] = receiver_username_len;
    if (receiver_username_len + 2 < receiver_username_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = receiver_username_len + 2;
    if (len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    if (2 + (unsigned long)msg < 2){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy((msg+2), selected_user.c_str(), receiver_username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int msg_len = len + signature_len;
    if (msg_len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(msg+len, signature, signature_len);
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"Error in the sendto of the authentication message."<<endl;
		exit(1);
	}
};

string SecureChatClient::waitForRTT(){
    // 3 | receiver_username_len | receiver_username | signature
    char* buf = (char*)malloc(AVAILABLE_USER_MAX_SIZE); //TODO: cambiare costante
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    cout<<"Waiting for RTT..."<<endl;
    unsigned int len = recv(this->server_socket, (void*)buf, AVAILABLE_USER_MAX_SIZE, 0);
    cout<<len<<endl;
    if (len < 0){
        cerr<<"Error in receiving a RTT from another user"<<endl;
        exit(1);
    }
    cout<<"RTT received!"<<endl;

    unsigned int message_type = buf[0];
    if (message_type != 3){
        cerr<<"Message type is not corresponding to 'RTT type'."<<endl;
        exit(1);
    }
    unsigned int sender_username_len = buf[1];
    if (sender_username_len > USERNAME_MAX_SIZE){
        cerr<<"Receiver Username length is over the upper bound."<<endl;
    }
    string sender_username;
    if (sender_username_len + 2 < sender_username_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int clear_message_len = sender_username_len + 2;
    if (clear_message_len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    sender_username.append(buf+2, sender_username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    if (clear_message_len + (unsigned long)buf < clear_message_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error"<<endl;
        exit(1);
    }

    return sender_username;
};

void SecureChatClient::sendResponse(string sender_username, unsigned int response){
    // 4 | response | 5 | mbala | digest
    char msg[RESPONSE_MAX_SIZE];
    msg[0] = 4; //Type = 4, response to request to talk message
    msg[1] = response;

    unsigned int username_len = sender_username.length();
    msg[2] = username_len;

    if (3 + username_len < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = 3 + username_len;
    if (len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    if (3 + (unsigned long)msg < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }

    memcpy(msg+3, sender_username.c_str(), username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int msg_len = len + signature_len;
    if (msg_len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(msg + len, signature, signature_len);
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"Error in the sendto of the Response to RTT message."<<endl;
		exit(1);
	}

    cout<<"Sending Response to RTT equal to "<<response<<endl;
};

unsigned int SecureChatClient::waitForResponse(){
    // 4 | response | 5 | mbala | digest
    char* buf = (char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    cout<<"Waiting for Response to RTT..."<<endl;
    unsigned int len = recv(this->server_socket, (void*)buf, AVAILABLE_USER_MAX_SIZE, 0);
    cout<<len<<endl;
    if (len < 0){
        cerr<<"Error in receiving a Response RTT from another user"<<endl;
        exit(1);
    }
    cout<<"Response to RTT received!"<<endl;

    unsigned int message_type = buf[0];
    if (message_type != 4){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl;
        exit(1);
    }

    unsigned int response = buf[1];

    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (3 + username_len < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int clear_message_len = 3 + username_len;
    if (clear_message_len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    string sender_username;
    sender_username.append(buf+3, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    if (clear_message_len + (unsigned long)buf < clear_message_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    memcpy(clear_message, buf, clear_message_len);

    if(Utility::verifyMessage(this->server_pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error"<<endl;
        exit(1);
    }

    cout<<"Received Response to RTT equal to "<<response<<endl;

    return response;
};

void SecureChatClient::logout(unsigned int authenticated){
    // 8 | 0/1 | [signature] []: only whether user is authenticated
    char msg[LOGOUT_MAX_SIZE];
    msg[0] = 8; //Type = 8, logout message
    msg[1] = authenticated;
    unsigned int len = 2;
    unsigned int msg_len = 2;
    if(authenticated == 1){
        unsigned char* signature;
        unsigned int signature_len;
        Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

        if (len + (unsigned long)msg < len){
            cerr<<"Wrap around"<<endl;
            exit(1);
        }
        if (len + signature_len < len){
            cerr<<"Wrap around"<<endl;
            exit(1);
        }
        msg_len = len + signature_len;
        if (msg_len > LOGOUT_MAX_SIZE){
            cerr<<"Access out-of-bound"<<endl;
            exit(1);
        }
        memcpy(msg+len, signature, signature_len);
    }
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"Error in the sendto of the logout message."<<endl;
		exit(1);
	}
    close(this->server_socket);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;

    cout<<"Byte da cifrare: "<<plaintext_len<<endl;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    cout<<"Byte cifrati: "<<ciphertext_len<<endl;
    EVP_EncryptFinal(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *decryptedtext){
	EVP_CIPHER_CTX *ctx;
	
	int plainlen, outlen;
	
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_256_ecb(), key, iv);
	EVP_DecryptUpdate(ctx, decryptedtext, &outlen, ciphertext, ciphertext_len);
  	plainlen = outlen;
  	int res = EVP_DecryptFinal(ctx, decryptedtext + outlen, &outlen);
  	if(res==0)
  		printf("Error in decryption!\n");
  	plainlen += outlen;
  	
  	EVP_CIPHER_CTX_free(ctx);

	return outlen;
}

void SecureChatClient::senderKeyEstablishment(string receiver_username, EVP_PKEY* peer_key){
    cout<<"Sender key establishment"<<endl;
    RAND_poll();
    unsigned char r[R_SIZE];
    RAND_bytes(r, R_SIZE);

    char m1[R_MSG_SIZE];
    m1[0] = 6;
    if (1 + (unsigned long)m1 < 1){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy(m1+1, r, R_SIZE);
    unsigned int len = R_SIZE + 1;

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, m1, len, &signature, &signature_len);

    if (len + (unsigned long)m1 < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int msg_len = len + signature_len;
    if (msg_len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(m1+len, signature, signature_len);

    if (send(this->server_socket, m1, msg_len, 0) < 0) { cerr<<"Error in the sendto of the message R."<<endl; exit(1); }
    cout<<"message R sent to"<<receiver_username<<endl;

    //Receiving m2 message from receiver_username
    char* m2 = (char*)malloc(M2_SIZE);
    if (!m2){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1);}
    len = recv(this->server_socket, (void*)m2, M2_SIZE, 0);
    if (len < 0) { cerr<<"Error in receiving M2 from another user"<<endl; exit(1); }

    //Verify message authenticity
    if(len <= SIGNATURE_SIZE) { cerr<<"Wrap around"<<endl; exit(1); }
    unsigned int clear_message_len = len-SIGNATURE_SIZE;
    signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if ((unsigned long)m2 + clear_message_len < (unsigned long)m2) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(signature, m2+clear_message_len, SIGNATURE_SIZE);
    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, m2, clear_message_len);
    if(Utility::verifyMessage(peer_key, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error while receiving message m1"<<endl; exit(1);
    }

    //Check if the two Rs are equal
    char R_received[R_SIZE];
    if (1 + R_SIZE < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    unsigned int message_len = R_SIZE+1;
    if (1 + (unsigned long)m2 < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(R_received, m2+1, R_SIZE);
    //TODO: fare meglio il confronto tra i due buffer contenenti R
    unsigned int ok = 0;
    for (int i = 0; i < R_SIZE; i++){ 
        if(r[i] != R_received[i]) { ok = 1; break; }
    }
    if(ok==1) { cout<<"Error !"<<endl; exit(1); }
    else { cout<<"Nonce R correctly exchanged between "<<username<<" and "<<receiver_username<<endl; }

    //key session generation
    RAND_poll();
    unsigned char k[R_SIZE];
    RAND_bytes(k, R_SIZE);

    unsigned char* Tpubk_received = (unsigned char*)malloc(PUBKEY_MSG_SIZE);
    if (!Tpubk_received) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if (message_len + (unsigned long)m2 < message_len) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(Tpubk_received, m2+message_len, PUBKEY_MSG_SIZE);
    if (message_len + PUBKEY_MSG_SIZE < message_len) { cerr<<"Wrap around"<<endl; exit(1); }
    message_len += PUBKEY_MSG_SIZE;

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, Tpubk_received, PUBKEY_MSG_SIZE);
    EVP_PKEY* tpubk = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);
/*
    unsigned char* ciphertext = (unsigned char *)malloc(sizeof(k)+16);

    // Encrypt utility function
    int ciphertext_len = encrypt(k, R_SIZE, Tpubk_received, NULL, ciphertext);

    char m3[M3_SIZE];
    m3[0] = 8;
    if (1 + (unsigned long)m3 < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(m3+1, ciphertext, ciphertext_len);
    if (1 + ciphertext_len < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    len = 1 + ciphertext_len;

    Utility::signMessage(client_prvkey, m3, len, &signature, &signature_len);
    if (len + (unsigned long)m3 < len){ cerr<<"Wrap around"<<endl; exit(1); }
    if (len + signature_len < len){ cerr<<"Wrap around"<<endl; exit(1); }
    unsigned int m3_len = len + signature_len;
    //if (msg_len > RESPONSE_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; exit(1); }
    if (len + (unsigned long)m3 < len){ cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(m3+len, signature, signature_len);

    if (send(this->server_socket, m3, m3_len, 0) < 0) { cerr<<"Error in the sendto of the m3 message."<<endl; exit(1); }
    cout<<"message m3 sent from "<<username<<" to "<<receiver_username<<endl;
*/    
    //TODO: delete Tpubk

}

void SecureChatClient::receiverKeyEstablishment(string sender_username, EVP_PKEY* peer_key){
    cout<<"Receiver key establishment"<<endl;
    char* m1 = (char*)malloc(R_MSG_SIZE);
    if (!m1){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    unsigned int len = recv(this->server_socket, (void*)m1, R_MSG_SIZE, 0);
    cout<<len<<endl;
    if (len < 0){
        cerr<<"Error in receiving M1 from another user"<<endl;
        exit(1);
    }

    if (m1[0] != 6){
        cerr<<"Received a message type different from 'key esablishment' type"<<endl;
        exit(1);
    }

    //Verify message authenticity
    if(len < SIGNATURE_SIZE) { cerr<<"Wrap around Michelo"<<endl; exit(1); }
    unsigned int clear_message_len = len-SIGNATURE_SIZE;
    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    if ((unsigned long)m1 + clear_message_len < (unsigned long)m1) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(signature, m1+clear_message_len, SIGNATURE_SIZE);
    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1); }
    memcpy(clear_message, m1, clear_message_len);
    if(Utility::verifyMessage(peer_key, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error while receiving message m1"<<endl; exit(1);
    }

    unsigned char r[R_SIZE];
    memcpy(r, m1+1, R_SIZE);
    cout<<"message R received from "<<sender_username<<endl;

    pid_t pid;
    char* argv1[5] = {strdup("genrsa"), strdup("-out"), strdup(""), strdup("3072"), NULL};
    EVP_PKEY* tprivk;
    string tprivk_path = "client/" + this->username + "/tprivk.pem";
    argv1[2] = (char*)malloc(tprivk_path.length()+1);
    if (!argv1[2]){
        cerr<<"Malloc didn't work"<<endl;
        exit(1);
    }
    strncpy(argv1[2], tprivk_path.c_str(), tprivk_path.length());
    argv1[2][tprivk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){
        execv("/bin/openssl", argv1);
        exit(0);
    }
    if (pid < 0){
        cerr<<"Error while creating a new process"<<endl;
        exit(1);
    }
    waitpid(pid, NULL, 0);
    FILE* file = fopen(tprivk_path.c_str(), "r");
    if(!file){
        cerr<<"Error while reading the file"<<endl;
        exit(1);
    }
    tprivk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!tprivk){
        cerr<<"Error while reading the private key"<<endl;
        exit(1);
    }
    fclose(file);

    string tpubk_path = "client/" + this->username + "/tpubk.pem";
    char* argv2[7] = {strdup("rsa"), strdup("-pubout"), strdup("-in"), strdup(""), strdup("-out"), strdup(""), NULL};
    argv2[3] = (char*)malloc(tprivk_path.length()+1);
    if (!argv2[3]){
        cerr<<"Malloc didn't work"<<endl;
        exit(1);
    }
    strncpy(argv2[3], tprivk_path.c_str(), tprivk_path.length());
    argv2[3][tprivk_path.length()] = '\0';
    argv2[5] = (char*)malloc(tpubk_path.length()+1);
    if (!argv2[5]){
        cerr<<"Malloc didn't work"<<endl;
        exit(1);
    }
    strncpy(argv2[5], tpubk_path.c_str(), tpubk_path.length());
    argv2[5][tpubk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){
        execv("/bin/openssl", argv2);
        exit(0);
    }
    if (pid < 0){
        cerr<<"Error while creating a new process"<<endl;
        exit(1);
    }
    waitpid(pid, NULL, 0);
    EVP_PKEY* tpubk;
    file = fopen(tpubk_path.c_str(), "r");
    if(!file){
        cerr<<"Error while reading the file"<<endl;
        exit(1);
    }
    tpubk = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!tpubk){
        cerr<<"Error while reading the public key"<<endl;
        exit(1);
    }
    fclose(file);
    char* argv3[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv3[1] = (char*)malloc(tpubk_path.length());
    if (!argv3[1]){
        cerr<<"Malloc didn't work"<<endl;
        exit(1);
    }
    strncpy(argv3[1], tpubk_path.c_str(), tpubk_path.length());
    argv3[1][tpubk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){
        execv("/bin/rm", argv3);
        exit(0);
    }
    if (pid < 0){
        cerr<<"Error while creating a new process"<<endl;
        exit(1);
    }
    waitpid(pid, NULL, 0);

    char* argv4[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv4[1] = (char*)malloc(tprivk_path.length());
    if (!argv4[1]){
        cerr<<"Malloc didn't work"<<endl;
        exit(1);
    }
    strncpy(argv4[1], tprivk_path.c_str(), tprivk_path.length());
    argv4[1][tprivk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){
        execv("/bin/rm", argv4);
        exit(0);
    }
    if (pid < 0){
        cerr<<"Error while creating a new process"<<endl;
        exit(1);
    }
    waitpid(pid, NULL, 0);

    // Send M2: <R || TpubKb>B
    //we don't send the certificate because the other peer has yet the public key
    char* m2 = (char*)malloc(M2_SIZE);
    if (!m2){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; exit(1);}

    m2[0] = 6;

    //inserting <R || TpubKb>B in the m2 message
    if (1 + (unsigned long)m2 < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(m2+1, r, R_SIZE);
    if (1 + R_SIZE < 1) { cerr<<"Wrap around"<<endl; exit(1); }
    len = 1 + R_SIZE;
    char* pubkey_buf = NULL;
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, tpubk);
    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    if (1 + pubkey_size > PUBKEY_MSG_SIZE) { cerr<<"Access out-of-bound"<<endl; exit(1); }
    if (len + (unsigned long)m2 < len) { cerr<<"Wrap around"<<endl; exit(1); }
    memcpy(m2+len, pubkey_buf, pubkey_size);
    if (pubkey_size + len < pubkey_size){ cerr<<"Wrap around"<<endl; exit(1); }
    len += pubkey_size;
        //unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, m2, len, &signature, &signature_len);
    if (len + (unsigned long)m2 < len) { cerr<<"Wrap around."<<endl; exit(1); }
    memcpy(m2+len, signature, signature_len);
    if (len + signature_len < len) { cerr<<"Wrap around."<<endl; exit(1); }
    len += signature_len;

    //sending m2 message to the sender_username
    if (send(this->server_socket, m2, len, 0) < 0) { cerr<<"Error in the sendto of the m2 message."<<endl; exit(1); }
    cout<<"message m2 sent from "<<username<<" to "<<sender_username<<endl;

    //TODO: inserire il controllo sul tipo di messaggio ricevuto

    unsigned char m4[M3_SIZE];

    //receiving m3 message from the sender_username
    len = recv(this->server_socket, (void*)m4, M3_SIZE, 0);
    if (len < 0){ cerr<<"Error in receiving message R from another user"<<endl; exit(1); }
    cout<<"message m3 received from "<<sender_username<<endl;
/*
    unsigned char* decryptedtext = (unsigned char *) malloc(sizeof(ciphertext));

    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL, decryptedtext);
*/
}
