#include "SecureChatClient.h"
#include <cstring>
#include <iostream>
#include <thread>
#include <map>

string SecureChatClient::username;
EVP_PKEY* SecureChatClient::client_prvkey = NULL;
X509* SecureChatClient::ca_certificate = NULL;
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

    //Send a message to authenticate to the server
    authenticateUser();

    //Print the user list and select a user to communicate with 
    string selected_user = receiveAvailableUsers();

    //Send request to talk to the selected user
    sendRTT(selected_user);
}

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

void SecureChatClient::authenticateUser(){

    if (username.length() >= USERNAME_MAX_SIZE){
        cerr<<"Username length too large."<<endl;
        exit(1);
    }

    //Message 0|len|"simeon"|prvk_simeon(digest)
    char msg[AUTHENTICATION_MAX_SIZE];
    msg[0] = 0; //Type = 0, authentication message
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
        pthread_exit(NULL);
    }
    cout<<"Authentication is ok"<<endl;

    if (clear_message_len < 2){
        cerr<<"Message format is not correct"<<endl;
        exit(1);
    }
    unsigned int message_type = buf[0];
    if (message_type != 1){
        cerr<<"The message type is not corresponding to 'user list'"<<endl;
        exit(1);
    }

    cout<<"Online Users"<<endl;
    unsigned int user_number = buf[1];
    unsigned int current_len = 2;
    unsigned int username_len;
    char current_username[USERNAME_MAX_SIZE];
    // 1 | 2 | 6 | simeon | 5 | mbala
    map<unsigned int, string> users_online;
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

    string selected;
    cout<<"Select the number corrisponding to the user you want to communicate with: ";
    cin>>selected;
    if(!cin) {exit(1);}

    while(!Utility::isNumeric(selected) || atoi(selected.c_str()) >= user_number){
        cout<<"Selected user number not valid! Select another number: ";
        cin>>selected;
        if(!cin) {exit(1);}
    }

    return users_online.at(atoi(selected.c_str()));
}

void SecureChatClient::sendRTT(string selected_user){
    // 2 / receiver_username_len / receiver_username / digest
    char msg[BUFFER_SIZE];
    msg[0] = 2; //Type = 2, request to talk message
    char receiver_username_len = selected_user.length(); //receiver_username length on one byte
    msg[1] = receiver_username_len;
    if (receiver_username_len + 2 < receiver_username_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = receiver_username_len + 2;
    if (len >= BUFFER_SIZE){
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
    if (msg_len >= BUFFER_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(msg + len, signature, signature_len);
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		cerr<<"Error in the sendto of the authentication message."<<endl;
		exit(1);
	}
};