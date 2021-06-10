#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include <openssl/x509.h>
#include <sys/select.h>
#include<signal.h>

EVP_PKEY* SecureChatServer::server_prvkey = NULL;
X509* SecureChatServer::server_certificate = NULL;
map<string, User>* SecureChatServer::users = NULL;

void sig_handler(int signum){
    for (map<string,User>::iterator it=(*SecureChatServer::users).begin(); it!=(*SecureChatServer::users).end(); ++it){
        close(it->second.socket);
    }
    exit(1);
}

SecureChatServer::~SecureChatServer(){
    close(this->listening_socket);
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function setups the server.                           *|
|*                                                            *|
\* ---------------------------------------------------------- */
SecureChatServer::SecureChatServer(const char *addr, unsigned short int port, const char *user_filename) {

    signal(2,sig_handler);

    /* ---------------------------------------------------------- *\
    |* Read the server private key                                *|
    \* ---------------------------------------------------------- */
    server_prvkey = getPrvKey();

    /* ---------------------------------------------------------- *\
    |* Read the server certificate                                *|
    \* ---------------------------------------------------------- */
    server_certificate = getCertificate();

    /* ---------------------------------------------------------- *\
    |* Set the server address and the server port in the          *|
    |* class instance                                             *|
    \* ---------------------------------------------------------- */
    strncpy(this->address, addr, MAX_ADDRESS_SIZE-1);
    this->address[MAX_ADDRESS_SIZE-1] = '\0';
    this->port = port;

    /* ---------------------------------------------------------- *\
    |* Set the user list in the class instance                    *|
    \* ---------------------------------------------------------- */
    this->users = loadUsers(user_filename);

    /* ---------------------------------------------------------- *\
    |* Setup the server socket                                    *|
    \* ---------------------------------------------------------- */
    setupSocket();

    /* ---------------------------------------------------------- *\
    |* Let the server listen to client requests                   *|
    \* ---------------------------------------------------------- */
    listenRequests();
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function gets the server private key.                 *|
|*                                                            *|
\* ---------------------------------------------------------- */
EVP_PKEY* SecureChatServer::getPrvKey() {
    server_prvkey = Utility::readPrvKey("./server/server_key.pem", NULL);
    return server_prvkey;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function gets the server private key.                 *|
|*                                                            *|
\* ---------------------------------------------------------- */
EVP_PKEY* SecureChatServer::getUserKey(string username) {
    string path = "./server/" + username + "_pubkey.pem";
    EVP_PKEY* username_pubkey = Utility::readPubKey(path.c_str(), NULL);
    return username_pubkey;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function gets the server certificate.                 *|
|*                                                            *|
\* ---------------------------------------------------------- */
X509* SecureChatServer::getCertificate(){
    server_certificate = Utility::readCertificate("./server/server_cert.pem");
    return server_certificate;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function setups the server socket.                    *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::setupSocket(){
    this->listening_socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&this->server_addr, 0, sizeof(this->server_addr));
	this->server_addr.sin_family = AF_INET;
	this->server_addr.sin_port = htons(this->port);
    inet_pton(AF_INET, this->address, &this->server_addr.sin_addr);
	cout<<"Thread "<<gettid()<<": Socket created to receive client requests."<<endl;

	if (bind(this->listening_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the bind"<<endl;
		exit(1);
	}

    if (listen(this->listening_socket, 10)){
        cerr<<"Thread "<<gettid()<<": Error in the listen"<<endl;
        exit(1);
    }

	cout<<"Thread "<<gettid()<<": Socket associated through bind."<<endl;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function contains the role of the main thread that    *|
|* listens to requests and starts new threads to handle them. *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::listenRequests(){
    pid_t pid;
    int new_socket;
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t addrlen = sizeof(struct sockaddr_in);
    addrlen = sizeof(client_addr);

    while(1){
        /* ---------------------------------------------------------- *\
        |* Waiting for a client request                               *|
        \* ---------------------------------------------------------- */
        new_socket = accept(this->listening_socket, (struct sockaddr*)&client_addr, &addrlen);
        if (new_socket < 0){
            cerr<<"Thread "<<gettid()<<"Error in the accept"<<endl;
            exit(1);
        }
        cout<<"Thread "<<gettid()<<": Request received by a client with address "<<inet_ntoa(client_addr.sin_addr)<<" and port "<<ntohs(client_addr.sin_port)<<endl;

        /* ---------------------------------------------------------- *\
        |* Create a new thread to handle the new connection           *|
        \* ---------------------------------------------------------- */
        thread handler (&SecureChatServer::handleConnection, this, new_socket, client_addr);
        handler.detach();
    }
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function handles a single client until he/she is      *|
|* linked to another client.                                  *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::handleConnection(int data_socket, sockaddr_in client_address){

    /* ---------------------------------------------------------- *\
    |* Send certificate to the new user                           *|
    \* ---------------------------------------------------------- */
    sendCertificate(data_socket);
    cout<<"Thread "<<gettid()<<": Certificate sent"<<endl;

    /* ---------------------------------------------------------- *\
    |* Receive authentication from the user                       *|
    \* ---------------------------------------------------------- */
    unsigned int status;
    string username = receiveAuthentication(data_socket, status);

    /* ---------------------------------------------------------- *\
    |* Change user status to 1 if the user is available to        *|
    |* receive a message                                          *|
    \* ---------------------------------------------------------- */
    changeUserStatus(username, status, data_socket);

    /* ---------------------------------------------------------- *\
    |* Print user list                                            *|
    \* ---------------------------------------------------------- */
    printUserList();

    /* ---------------------------------------------------------- *\
    |* Sender case                                                *|
    \* ---------------------------------------------------------- */
    if(status == 0){
        /* ---------------------------------------------------------- *\
        |* Send the list of users that are available to receive       *|
        \* ---------------------------------------------------------- */
        sendAvailableUsers(data_socket, username);
        
        /* ---------------------------------------------------------- *\
        |* Server's thread receive the RTT message                    *|
        \* ---------------------------------------------------------- */
        string receiver_username = receiveRTT(data_socket, username);

        /* ---------------------------------------------------------- *\
        |* Server forwards the RTT to the final receiver              *|
        \* ---------------------------------------------------------- */
        changeUserStatus(receiver_username, 0, 0);
        forwardRTT(receiver_username, username);

        /* ---------------------------------------------------------- *\
        |* Wait on the condition variable of the receiver             *|
        \* ---------------------------------------------------------- */
        wait(receiver_username);

        /* ---------------------------------------------------------- *\
        |* Check if the request has been accepted                     *|
        \* ---------------------------------------------------------- */
        pthread_mutex_lock(&(*users).at(username).user_mutex);
        if((*users).at(receiver_username).responses.at(username) != 1) { pthread_exit(NULL); }
        pthread_mutex_unlock(&(*users).at(username).user_mutex);

        /* ---------------------------------------------------------- *\
        |* Starts a new thread to handle the chat                     *|
        \* ---------------------------------------------------------- */
        int receiver_socket = (*users).at(receiver_username).socket;
        thread handler (&SecureChatServer::handleChat, this, data_socket, receiver_socket, username, receiver_username);
        handler.detach();

    }
    /* ---------------------------------------------------------- *\
    |* Receiver case                                              *|
    \* ---------------------------------------------------------- */
    if (status == 1){ //user wants to receive a message
        /* ---------------------------------------------------------- *\
        |* Server waits for the response (accept or refuse)           *|
        |* from the final receiver                                    *|
        \* ---------------------------------------------------------- */
        unsigned int response;
        string sender_username = receiveResponse(data_socket, username, response);

        /* ---------------------------------------------------------- *\
        |* Server forwards the response to the sender                 *|
        \* ---------------------------------------------------------- */
        forwardResponse(sender_username, response);

        /* ---------------------------------------------------------- *\
        |* Frees the other thread that is handling the sender         *|
        \* ---------------------------------------------------------- */
        notify(username);
    }

    pthread_exit(NULL);
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function handles a chat betweem two clients.          *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::handleChat(int sender_socket, int receiver_socket, string sender, string receiver){
     /* ---------------------------------------------------------- *\
    |* Server sends receiver public key to the sender user        *|
    \* ---------------------------------------------------------- */
    sendUserPubKey(receiver, sender_socket);
    sendUserPubKey(sender, receiver_socket);

    /* ---------------------------------------------------------- *\
    |* *************************   M1   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Server receives the message M1 from the sender user        *|
    \* ---------------------------------------------------------- */
    char m1[M1_SIZE];
    unsigned int len;
    receive(sender_socket, sender, len, m1, M1_SIZE);

    /* ---------------------------------------------------------- *\
    |* Server forwards the message M1 to the receiver user        *|
    \* ---------------------------------------------------------- */
    forward(receiver, m1, len);


    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Server receives the message M2 from the receiver user      *|
    \* ---------------------------------------------------------- */
    char m2[M2_SIZE];
    receive(receiver_socket, receiver, len, m2, M2_SIZE);

    /* ---------------------------------------------------------- *\
    |* Server forwards the message M2 to the sender user          *|
    \* ---------------------------------------------------------- */
    forward(sender, m2, len);


    /* ---------------------------------------------------------- *\
    |* *************************   M3   ************************* *|
    \* ---------------------------------------------------------- */


    /* ---------------------------------------------------------- *\
    |* Server receives the message M3 from the sender user        *|
    \* ---------------------------------------------------------- */
    char m3[M3_SIZE];
    receive(sender_socket, sender, len, m3, M3_SIZE);

    /* ---------------------------------------------------------- *\
    |* Server forwards the message M3 to the receiver user        *|
    \* ---------------------------------------------------------- */
    forward(receiver, m3, len);

    fd_set master, copy;
    FD_ZERO(&master);

    FD_SET(sender_socket, &master);
    FD_SET(receiver_socket, &master);

    while(true){
        copy = master;

        int socket_count = select(FD_SETSIZE, &copy, NULL, NULL, NULL);

		if (FD_ISSET(sender_socket, &copy)){
            char msg[GENERAL_MSG_SIZE];
            unsigned int len;
            receive(sender_socket, sender, len, msg, GENERAL_MSG_SIZE);
            checkLogout(sender_socket, receiver_socket, msg, len, 1, sender, receiver);
            forward(receiver, msg, len);
        }
        if (FD_ISSET(receiver_socket, &copy)){
            char msg[GENERAL_MSG_SIZE];
            unsigned int len;
            receive(receiver_socket, receiver, len, msg, GENERAL_MSG_SIZE);
            checkLogout(receiver_socket, sender_socket, msg, len, 1, receiver, sender);
            forward(sender, msg, len);
        }
    }
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function sends the certificate to a user.             *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::sendCertificate(int data_socket){

    /* ---------------------------------------------------------- *\
    |* Serialize the certificate                                  *|
    \* ---------------------------------------------------------- */
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, server_certificate);
    char* certificate_buf = NULL;
    long certificate_size = BIO_get_mem_data(mbio, &certificate_buf);
	
    /* ---------------------------------------------------------- *\
    |* Send the certificate                                       *|
    \* ---------------------------------------------------------- */
	if (send(data_socket, certificate_buf, certificate_size, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the sendto of the message containing the certificate."<<endl;
		pthread_exit(NULL);
	}

    BIO_free(mbio);
	return;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function sends the public key of a user to            *|
|* another user.                                              *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::sendUserPubKey(string username, int data_socket){

    char buf[PUBKEY_MSG_SIZE];
    char* pubkey_buf = NULL;
    buf[0] = 5;

    EVP_PKEY* pubkey = getUserKey(username);

    /* ---------------------------------------------------------- *\
    |* Serialize the public key                                   *|
    \* ---------------------------------------------------------- */
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, pubkey);

    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    if (1 + pubkey_size < 1){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int len = 1 + pubkey_size;
    if (1 + pubkey_size > PUBKEY_MSG_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    memcpy(buf+1, pubkey_buf, pubkey_size);
    BIO_free(mbio);

    /* ---------------------------------------------------------- *\
    |* Sign the message                                           *|
    \* ---------------------------------------------------------- */
    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, buf, len, &signature, &signature_len);

    if (len + signature_len < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (len + signature_len > PUBKEY_MSG_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    if (len + (unsigned long)buf < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int msg_len = len + signature_len;
    memcpy(buf+len, signature, signature_len);
	
    /* ---------------------------------------------------------- *\
    |* Send the message                                           *|
    \* ---------------------------------------------------------- */
	if (send(data_socket, buf, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the sendto of the message containing the public key to "<<username<<endl;
		pthread_exit(NULL);
	}
    Utility::printMessage(("Pubkey di " + username).c_str(), (unsigned char*)buf, msg_len);
	return;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function receives the authentitcation message         *|
|* from the client and verifies it.                           *|
|*                                                            *|
\* ---------------------------------------------------------- */
string SecureChatServer::receiveAuthentication(int data_socket, unsigned int &status){
    /* ---------------------------------------------------------- *\
    |* Receive the authentication message                         *|
    \* ---------------------------------------------------------- */
    char* authentication_buf = (char*)malloc(AUTHENTICATION_MAX_SIZE);
    if (!authentication_buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    unsigned int authentication_len = recv(data_socket, (void*)authentication_buf, AUTHENTICATION_MAX_SIZE, 0);
    if (authentication_len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the authentication message"<<endl;
        exit(1);
    }

    /* ---------------------------------------------------------- *\
    |* Check if the message is a logout message                   *|
    \* ---------------------------------------------------------- */
    checkLogout(data_socket, 0, authentication_buf, authentication_len, 0, "", "");

    cout<<"Thread "<<gettid()<<": Authentication message received"<<endl;

    /* ---------------------------------------------------------- *\
    |* Extract the fields from the message                        *|
    \* ---------------------------------------------------------- */
    status = authentication_buf[0];
    if (status != 0 && status != 1){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'authentication type'."<<endl;
        exit(1);
    }
    unsigned int username_len = authentication_buf[1];
    if (username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Username length is over the upper bound."<<endl;
    }
    string username;
    if (2 + (unsigned long)authentication_buf < 2){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    username.append(authentication_buf+2, username_len);

    if(authentication_len < SIGNATURE_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = authentication_len - SIGNATURE_SIZE;
    if(clear_message_len < 2) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    clear_message_len -= 2;
    if(clear_message_len < username_len) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    clear_message_len -= username_len;
    /* ---------------------------------------------------------- *\
    |* Initialize variables for decrypting                        *|
    \* ---------------------------------------------------------- */
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    unsigned int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned int encrypted_key_len = EVP_PKEY_size(this->server_prvkey);
    unsigned int cphr_size = clear_message_len - encrypted_key_len - iv_len;
    unsigned int plaintext_len;
    unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    unsigned char* ciphertext = (unsigned char*)malloc(cphr_size);
    unsigned char* plaintext = (unsigned char*)malloc(cphr_size);
    if(!encrypted_key || !iv || !ciphertext || !plaintext) { cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }    

    /* ---------------------------------------------------------- *\
    |* Insert the fields from logout nonce message                *|
    |* into the respective variables                              *|
    \* ---------------------------------------------------------- */
    unsigned int index = 2 + username_len;
    if (index + (unsigned long)authentication_buf < index){ cerr<<"Wrap around."<<endl; pthread_exit(NULL); }
    memcpy(ciphertext, authentication_buf + index, cphr_size);
    index += cphr_size;
    if (index + (unsigned long)authentication_buf < index){ cerr<<"Wrap around."<<endl; pthread_exit(NULL); }
    memcpy(iv, authentication_buf+index, iv_len);
    if (index + iv_len < index){ cerr<<"Wrap around."<<endl; pthread_exit(NULL); }
    index += iv_len;
    if (index + (unsigned long)authentication_buf < index){ cerr<<"Wrap around."<<endl; pthread_exit(NULL); }
    memcpy(encrypted_key, authentication_buf+index, encrypted_key_len);

    /* ---------------------------------------------------------- *\
    |* Decrypt the message                                        *|
    \* ---------------------------------------------------------- */
    if (!Utility::decryptMessage(plaintext, ciphertext, cphr_size, iv, encrypted_key, encrypted_key_len, this->server_prvkey, plaintext_len)) { cerr<<"Error while decrypting"<<endl; pthread_exit(NULL); }

    /* ---------------------------------------------------------- *\
    |* Verify the authenticity of the message                     *|
    \* ---------------------------------------------------------- */
    if(authentication_len < SIGNATURE_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int signed_message_len = authentication_len - SIGNATURE_SIZE;
    if ((unsigned long)authentication_buf + signed_message_len < signed_message_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    EVP_PKEY* pubkey = getUserKey(username);

    if(Utility::verifyMessage(pubkey, authentication_buf, signed_message_len, (unsigned char*)((unsigned long)authentication_buf+signed_message_len), SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error while receiving the authentication"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication of authentication message is ok"<<endl;

    Utility::printMessage("Logout nonce message: ", plaintext, plaintext_len);
    /* ---------------------------------------------------------- *\
    |* Analyze the content of the plaintext                       *|
    \* ---------------------------------------------------------- */

    memcpy((*users).at(username).logout_nonce, plaintext, NONCE_SIZE);

    return username;
}


/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function changes the status of a user.                *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::changeUserStatus(string username, unsigned int status, int user_socket){
    cout<<"changeUserStatus(): "<<username<<", "<<status<<endl;
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).status = status;
    if (user_socket != 0)
        (*users).at(username).socket = user_socket;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
    cout<<"Change user status finita"<<endl;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function prints the list of users.                    *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::printUserList(){
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        it->second.printUser();
    }
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function retrieves the list of online users.          *|
|*                                                            *|
\* ---------------------------------------------------------- */
vector<User> SecureChatServer::getOnlineUsers(){
    vector<User> v;
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        pthread_mutex_lock(&(it->second.user_mutex));
        if (it->second.status == 1){
            v.push_back(it->second);
        }
        pthread_mutex_unlock(&(it->second.user_mutex));
    }
    return v;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function sends the list of available users.           *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::sendAvailableUsers(int data_socket, string username){
    char buf[AVAILABLE_USER_MAX_SIZE];
    buf[0] = 2;

    /* ---------------------------------------------------------- *\
    |* Retrive the list of online users.                          *|
    \* ---------------------------------------------------------- */
    vector<User> available = getOnlineUsers();
    if (available.size() > MAX_AVAILABLE_USER_MESSAGE){ buf[1] = MAX_AVAILABLE_USER_MESSAGE; }
    else{ buf[1] = available.size(); }
    unsigned int len = 2;
    /* ---------------------------------------------------------- *\
    |* Format: type=2|num_users|len1|user1|len2|user2|...         *|
    \* ---------------------------------------------------------- */
    for (unsigned int i = 0; i < available.size(); i++){
        if (available[i].username.compare(username) != 0){
            if (len >= AVAILABLE_USER_MAX_SIZE){ cerr<<"Access our-of-bound"<<endl; pthread_exit(NULL); }
            buf[len] = available[i].username.length();
            if (len + 1 == 0){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
            len++;
            if (len + (unsigned long)buf < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
            if (len + available[i].username.length() < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
            if (len + available[i].username.length() >= AVAILABLE_USER_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
            memcpy(buf+len, available[i].username.c_str(), available[i].username.length());
            len += available[i].username.length();
        }
    }

    /* ---------------------------------------------------------- *\
    |* Sign the message.                                          *|
    \* ---------------------------------------------------------- */
    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, buf, len, &signature, &signature_len);

    if (len + signature_len < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (len + signature_len >= AVAILABLE_USER_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    if (len + (unsigned long)buf < len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int msg_len = len + signature_len;
    memcpy(buf+len, signature, signature_len);

    /* ---------------------------------------------------------- *\
    |* Send the message.                                          *|
    \* ---------------------------------------------------------- */
    
    if (send(data_socket, buf, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<"Error in the sendto of the available user list"<<endl;
		pthread_exit(NULL);
	}

}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function receives the Request to Talk from the user.  *|
|*                                                            *|
\* ---------------------------------------------------------- */
string SecureChatServer::receiveRTT(int data_socket, string username){
    char* buf = (char*)malloc(RTT_MAX_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }

    unsigned int len = recv(data_socket, (void*)buf, RTT_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the RTT message"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": RTT message received"<<endl;

    checkLogout(data_socket, 0, buf, len, 1, username, "");

    unsigned int message_type = buf[0];
    if (message_type != 3){ cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'RTT type'."<<endl; pthread_exit(NULL); }
    unsigned int receiver_username_len = buf[1];
    if (receiver_username_len > USERNAME_MAX_SIZE){ cerr<<"Thread "<<gettid()<<": Receiver Username length is over the upper bound."<<endl; }
    string receiver_username;
    if (receiver_username_len + 2 < receiver_username_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = receiver_username_len + 2;
    if (clear_message_len >= RTT_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    receiver_username.append(buf+2, receiver_username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication of RTT is ok"<<endl;

    return receiver_username;
}

void SecureChatServer::forwardRTT(string receiver_username, string sender_username){
    //TODO gestire la RTT inviandola al receiver
    int data_socket = (*users).at(receiver_username).socket;
    // 3 | sender_username_len | sender_username | digest
    char msg[RTT_MAX_SIZE];
    msg[0] = 3; //Type = 3, request to talk message
    unsigned int sender_username_len = sender_username.length(); //receiver_username length on one byte
    msg[1] = sender_username_len;
    if (sender_username_len + 2 < sender_username_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = sender_username_len + 2;
    if (len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    if (2 + (unsigned long)msg < 2){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy((msg+2), sender_username.c_str(), sender_username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

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
    memcpy(msg + len, signature, signature_len);
    
    unsigned int ret = send(data_socket, msg, msg_len, 0);
    if (ret < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the RTT with error "<<ret<<endl;
		pthread_exit(NULL);
	}
}

string SecureChatServer::receiveResponse(int data_socket, string receiver_username, unsigned int &response){
    // 4 | response | 5 | mbala | digest
    char* buf = (char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }

    unsigned int len = recv(data_socket, (void*)buf, RESPONSE_MAX_SIZE, 0);
    if (len < 0){ cerr<<"Thread "<<gettid()<<": Error in receiving the Response to RTT message"<<endl; pthread_exit(NULL);}
    cout<<"Thread "<<gettid()<<": Response to RTT message received"<<endl;

    checkLogout(data_socket, 0, buf, len, 1, receiver_username, "");
    unsigned int message_type = buf[0];
    if (message_type != 4){ cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl; pthread_exit(NULL);}

    response = buf[1];

    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (3 + username_len < 3){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = 3 + username_len;
    if (clear_message_len > RESPONSE_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    string sender_username;
    sender_username.append(buf+3, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(receiver_username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error for Response to RTT"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Response to RTT received equal to "<<response<<endl;

    if ((*users).at(receiver_username).responses.count(sender_username)!=0)
        (*users).at(receiver_username).responses.at(sender_username) = response;
    else
        (*users).at(receiver_username).responses.insert(pair<string, unsigned int>(sender_username, response));

    return sender_username;
}

void SecureChatServer::forwardResponse(string sender_username, unsigned int response){
    int data_socket = (*users).at(sender_username).socket;
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
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

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
    
    if (send(data_socket, msg, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }
}

void SecureChatServer::checkLogout(int data_socket, int other_socket, char* msg, unsigned int buffer_len, unsigned int auth_required, string username, string other_username){
    if(msg[0] != 8)
        return;

    if(msg[1] == 0){
        if(auth_required == 1) //it is not possible to accept logout
            return;
        close(data_socket);
        cout<<"logout completed correctly"<<endl;
        pthread_exit(NULL);
    }
    else{
        unsigned int len = 2;
        unsigned char* logout_nonce = (unsigned char*)malloc(NONCE_SIZE);
        if (!logout_nonce){
            cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
            pthread_exit(NULL);
        }
        if (len + (unsigned long)msg < len){
            cerr<<"Wrap around"<<endl;
            pthread_exit(NULL);
        }
        
        memcpy(logout_nonce, msg+len, NONCE_SIZE);
        len += NONCE_SIZE;

        unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
        if (!signature){
            cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
            pthread_exit(NULL);
        }
        if (len + (unsigned long)msg < len){
            cerr<<"Wrap around"<<endl;
            pthread_exit(NULL);
        }
        memcpy(signature, msg+len, SIGNATURE_SIZE);

        char* clear_message = (char*)malloc(len);
        if (!clear_message){
            cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
            pthread_exit(NULL);
        }
        memcpy(clear_message, msg, len);

        EVP_PKEY* pubkey = getUserKey(username);

        if(Utility::verifyMessage(pubkey, clear_message, len, signature, SIGNATURE_SIZE) != 1) { 
            cerr<<"Thread "<<gettid()<<": logout not accepted"<<endl;
            return;
        }
        
        if(memcmp(logout_nonce, (*users).at(username).logout_nonce, NONCE_SIZE) == 0){;
            close(data_socket);
            if(other_socket != 0){
                close(other_socket);
                cout<<"Comunication between "<<username<<" and "<<other_username<<" correctly closed"<<endl;
            } else { cout<<username<<" logout completed correctly"<<endl; }
            pthread_exit(NULL);
        } else { cerr<<"Thread "<<gettid()<<": logout nonce not corresponding"<<endl;
            return;
        }
    }
}

void SecureChatServer::receive(int data_socket, string username, unsigned int &len, char* buf, const unsigned int max_size){
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }

    len = recv(data_socket, (void*)buf, max_size, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving a message"<<endl;
        pthread_exit(NULL);
    } else if (len == 0) { return; }
    /* ---------------------------------------------------------- *\
    |* Verify message authenticity                                *|
    \* ---------------------------------------------------------- */
    if(len < SIGNATURE_SIZE) { cerr<<"Wrap around1"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if ((unsigned long)buf + clear_message_len < (unsigned long)buf) { cerr<<"Wrap around2"<<endl; pthread_exit(NULL); }
    Utility::printMessage("Message received:", (unsigned char*)buf, len);
    if(Utility::verifyMessage(getUserKey(username), buf, clear_message_len, (unsigned char*)((unsigned long)buf+clear_message_len), SIGNATURE_SIZE) != 1) { 
        cerr<<"Authentication error while receiving message"<<endl; pthread_exit(NULL);
    }
}

void SecureChatServer::forward(string username, char* msg, unsigned int len){    
    int data_socket = (*users).at(username).socket;
    if (send(data_socket, msg, len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }
}

//to wait the Response message of the receiver before checking the response value in the thread of the sender
void SecureChatServer::wait(string username){
    unique_lock<mutex> lck((*users).at(username).mtx);
    while(!(*users).at(username).ready)
            (*users).at(username).cv.wait(lck);
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).ready = 0;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
}

//to notify that the Response message has been received before checking the response value in the thread of the sender
void SecureChatServer::notify(string username){
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).ready = 1;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
    (*users).at(username).cv.notify_all();
}