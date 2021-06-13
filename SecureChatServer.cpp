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

/* ---------------------------------------------------------- *\
|* Close each client socket when the server shutdown          *|
\* ---------------------------------------------------------- */
void sig_handler(int signum){
    for (map<string,User>::iterator it=(*SecureChatServer::users).begin(); it!=(*SecureChatServer::users).end(); ++it){
        close(it->second.socket);
    }
    exit(1);
}

/* ---------------------------------------------------------- *\
|* Class Destructor                                           *|
\* ---------------------------------------------------------- */
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
    |* Create R_server                                            *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    unsigned char R_server[R_SIZE];
    RAND_bytes(R_server, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Send certificate to the new user (S1)                      *|
    \* ---------------------------------------------------------- */
    cout<<"Thread "<<gettid()<<": Starting Key Establishment with the new client"<<endl;
    sendCertificate(data_socket, R_server);
    cout<<"Thread "<<gettid()<<": Message S1 sent"<<endl;

    /* ---------------------------------------------------------- *\
    |* Receive authentication from the user (S2)                  *|
    \* ---------------------------------------------------------- */
    unsigned int status;
    unsigned char* R_user; 
    EVP_PKEY* tpubk;
    string username = receiveAuthentication(data_socket, status, R_server, R_user, tpubk);
    cout<<"Thread "<<gettid()<<": Message S2 received"<<endl;

    /* ---------------------------------------------------------- *\
    |* Change user status to 1 if the user is available to        *|
    |* receive a message                                          *|
    \* ---------------------------------------------------------- */
    changeUserStatus(username, status, data_socket);

    /* ---------------------------------------------------------- *\
    |* Print user list                                            *|
    \* ---------------------------------------------------------- */
    printUserList();

    //TODO: generare K e inviare S3
    //S3 = nonce_user firmato,  E(tpubk,K), IV e encrypted key in chiaro

    /* ---------------------------------------------------------- *\
    |* Create K                                                   *|
    \* ---------------------------------------------------------- */
    RAND_poll();
    unsigned char K[K_SIZE];
    RAND_bytes(K, K_SIZE);

    unsigned char* iv;
    sendS3Message(data_socket, K, R_user, tpubk, iv);

    storeK(username, K);
    setCounters(iv, username);

    cout<<"Thread "<<gettid()<<": Message S3 sent"<<endl;

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
        forwardResponse(sender_username, username, response);

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
    |* 6 | R(16) | sender_signature (256)                         *|
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
    cout<<"Thread "<<gettid()<<": M1 message sent from "<<sender<<" to "<<receiver<<endl;

    /* ---------------------------------------------------------- *\
    |* *************************   M2   ************************* *|
    |* 6 | R(16) | tpubkey(451) | sender_signature (256)          *|
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
    cout<<"Thread "<<gettid()<<": M2 message sent from "<<receiver<<" to "<<sender<<endl;

    /* ------------------------------------------------------------------------------------ *\
    |* **********************************   M3   ****************************************** *|
    |* 6 | R(16) | E(tpubk, K)(16) | IV(16) | encrypted_key(384) | sender_signature (256)   *|
    \* ------------------------------------------------------------------------------------ */


    /* ---------------------------------------------------------- *\
    |* Server receives the message M3 from the sender user        *|
    \* ---------------------------------------------------------- */
    char m3[M3_SIZE];
    receive(sender_socket, sender, len, m3, M3_SIZE);

    /* ---------------------------------------------------------- *\
    |* Server forwards the message M3 to the receiver user        *|
    \* ---------------------------------------------------------- */
    forward(receiver, m3, len);
    cout<<"Thread "<<gettid()<<": M3 message sent from "<<sender<<" to "<<receiver<<endl;
    
    fd_set master, copy;
    FD_ZERO(&master);

    FD_SET(sender_socket, &master);
    FD_SET(receiver_socket, &master);

    while(true){
        copy = master;

        int socket_count = select(FD_SETSIZE, &copy, NULL, NULL, NULL);

        /* ---------------------------------------------------------- *\
        |* Read the server private key                                *|
        \* ---------------------------------------------------------- */
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
void SecureChatServer::sendCertificate(int data_socket, unsigned char* R_server){
    char* buf = (char*)malloc(S1_SIZE);
    memcpy(buf, R_server, R_SIZE);
    //TODO: aggiungere nonce_server in chiaro da mandare allo user
    /* ---------------------------------------------------------- *\
    |* Serialize the certificate                                  *|
    \* ---------------------------------------------------------- */
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, server_certificate);
    char* certificate_buf = NULL;
    long certificate_size = BIO_get_mem_data(mbio, &certificate_buf);
	
    if (R_SIZE + certificate_size < R_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (R_SIZE + (unsigned long)buf < R_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (R_SIZE + certificate_size > S1_SIZE) { cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    memcpy(buf+R_SIZE, certificate_buf, certificate_size);
    /* ---------------------------------------------------------- *\
    |* Send the certificate                                       *|
    \* ---------------------------------------------------------- */
    if (R_SIZE + certificate_size < R_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
	if (send(data_socket, buf, R_SIZE + certificate_size, 0) < 0){
		cerr<<"Error in the sendto of the message containing the certificate."<<endl;
		pthread_exit(NULL);
	}

    BIO_free(mbio);
	return;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function sends the message S3 to a user.              *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::sendS3Message(int data_socket, unsigned char* K, unsigned char* R_user, EVP_PKEY* tpubk, unsigned char* &iv){
    char* buf = (char*)malloc(S3_SIZE);
    buf[0] = 1;
    Utility::secure_thread_memcpy((unsigned char*)buf, 1, S3_SIZE, R_user, 0, R_SIZE, R_SIZE);

    /* ---------------------------------------------------------- *\
    |* Encrypt K using TpubK                                      *|
    \* ---------------------------------------------------------- */
    unsigned int len = 1+R_SIZE;
    unsigned char plaintext[K_SIZE];
    unsigned char* encrypted_key, *ciphertext;
    unsigned int cipherlen;
    int outlen, encrypted_key_len;
    Utility::secure_thread_memcpy(plaintext, 0, K_SIZE, K, 0, K_SIZE, K_SIZE);

    if (!Utility::encryptMessage(K_SIZE, tpubk, plaintext, ciphertext, encrypted_key, iv, encrypted_key_len, outlen, cipherlen)){ cerr<<"ERR: Error while encrypting"<<endl; pthread_exit(NULL); }
    Utility::secure_thread_memcpy((unsigned char*)buf, len, S3_SIZE, ciphertext, 0, K_SIZE+16, cipherlen);
    len += cipherlen;
    Utility::secure_thread_memcpy((unsigned char*)buf, len, S3_SIZE, iv, 0, BLOCK_SIZE, BLOCK_SIZE);
    len += BLOCK_SIZE;
    Utility::secure_thread_memcpy((unsigned char*)buf, len, S3_SIZE, encrypted_key, 0, EVP_PKEY_size(tpubk), encrypted_key_len);
    len += encrypted_key_len;

    /* ---------------------------------------------------------- *\
    |* Sign the R_user                                            *|
    \* ---------------------------------------------------------- */
    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, (char*)R_user, R_SIZE, &signature, &signature_len);
    Utility::secure_thread_memcpy((unsigned char*)buf, len, S3_SIZE, signature, 0, SIGNATURE_SIZE, signature_len);
    len += SIGNATURE_SIZE;


    /* ---------------------------------------------------------- *\
    |* Send the M3 message                                        *|
    \* ---------------------------------------------------------- */
    if (send(data_socket, buf, len, 0) < 0) { 
        cerr<<"ERR: Error in the sendto of the message S3"<<endl; 
        exit(1); 
    }

    /* ---------------------------------------------------------- *\
    |* Delete TpubK                                               *|
    \* ---------------------------------------------------------- */
    EVP_PKEY_free(tpubk);
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
	return;
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function receives the authentitcation message         *|
|* from the client and verifies it.                           *|
|*                                                            *|
\* ---------------------------------------------------------- */
string SecureChatServer::receiveAuthentication(int data_socket, unsigned int &status, unsigned char* R_server, unsigned char* &R_user, EVP_PKEY* &tpubk){
    //TODO: aggiungere ricezione nonce_user e tpubk in chiaro dallo user
    // nonce_server tpubk e ruolo firmati
    /* ---------------------------------------------------------- *\
    |* Receive the authentication message                         *|
    \* ---------------------------------------------------------- */
    char* buf = (char*)malloc(S2_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    unsigned int len = recv(data_socket, (void*)buf, S2_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the authentication message"<<endl;
        exit(1);
    }

    cout<<"Thread "<<gettid()<<": Authentication message received"<<endl;
    /* ---------------------------------------------------------- *\
    |* Extract the fields from the message                        *|
    \* ---------------------------------------------------------- */
    unsigned int tpubk_len_index = 1 + 2*R_SIZE;
    long tpubk_len;
    Utility::secure_thread_memcpy((unsigned char*)&tpubk_len, 0, sizeof(long), (unsigned char*)buf, tpubk_len_index, S2_SIZE, sizeof(long));
    unsigned int username_index = 1 + 2*R_SIZE + sizeof(long) + tpubk_len;
    unsigned int signed_msg_len = username_index;
    unsigned int username_len = buf[username_index];
    if (1 + username_index < 1){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    username_index++;
    if (username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Username length is over the upper bound."<<endl;
    }
    string username;
    if (username_index + (unsigned long)buf < username_index){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    username.append(buf+username_index, username_len);

    if(len < SIGNATURE_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if(clear_message_len < 2) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    clear_message_len -= 2; //TODO: controllare
    if(clear_message_len < username_len) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    clear_message_len -= username_len;

    /* ---------------------------------------------------------- *\
    |* Verify the authenticity of the message                     *|
    \* ---------------------------------------------------------- */
    if ((unsigned long)buf + signed_msg_len < signed_msg_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if (len < SIGNATURE_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
    if(Utility::verifyMessage(getUserKey(username), buf, signed_msg_len, (unsigned char*)((unsigned long)buf+len-SIGNATURE_SIZE), SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error while receiving the authentication"<<endl;
        pthread_exit(NULL);
    }

    unsigned char* R_server_received = (unsigned char*)malloc(R_SIZE);
    R_user = (unsigned char*)malloc(R_SIZE);

    Utility::secure_thread_memcpy(R_server_received, 0, R_SIZE, (unsigned char*)buf, 1, len, R_SIZE);
    if(Utility::compareR(R_server, R_server_received) == false) {
        cerr<<"Thread "<<gettid()<<": R_server not corrisponding"<<endl;
        pthread_exit(NULL);
    }
    
    /* ---------------------------------------------------------- *\
    |* Analyze the content of the plaintext                       *|
    \* ---------------------------------------------------------- */

    Utility::secure_thread_memcpy(R_user, 0, R_SIZE, (unsigned char*)buf, 1+R_SIZE, len, R_SIZE);
    /* ---------------------------------------------------------- *\
    |* Read the TpubK                                             *|
    \* ---------------------------------------------------------- */
    unsigned int tpubk_index = 1 + 2*R_SIZE + sizeof(long); 
    BIO* mbio = BIO_new(BIO_s_mem());
    if(tpubk_index + (unsigned long)buf < tpubk_index ) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    BIO_write(mbio, buf + tpubk_index, tpubk_len);
    tpubk = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    status = buf[0];
    if (status != 0 && status != 1){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'authentication type'."<<endl;
        exit(1);
    }

    return username;
}


/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function changes the status of a user.                *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::changeUserStatus(string username, unsigned int status, int user_socket){
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).status = status;
    if (user_socket != 0)
        (*users).at(username).socket = user_socket;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
}

void SecureChatServer::setCounters(unsigned char* iv, string username){
    Utility::secure_thread_memcpy((unsigned char*)&(*users).at(username).server_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_thread_memcpy((unsigned char*)&(*users).at(username).user_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    Utility::secure_thread_memcpy((unsigned char*)&(*users).at(username).base_counter, 0, sizeof(__uint128_t), iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), sizeof(__uint128_t));
    memset((unsigned char*)(&(*users).at(username).server_counter)+12, 0, 4);
    memset((unsigned char*)(&(*users).at(username).user_counter)+12, 0, 4);
    memset((unsigned char*)(&(*users).at(username).base_counter)+12, 0, 4);
}

void SecureChatServer::incrementCounter(int counter, string username){
    //counter = 0 -> server, counter = 1 -> user
    if (counter == 0){
        (*users).at(username).server_counter++;
        memset((unsigned char*)(&(*users).at(username).server_counter)+12, 0, 4);
        return;
    }
    if (counter == 1){
        (*users).at(username).user_counter++;
        memset((unsigned char*)(&(*users).at(username).user_counter)+12, 0, 4);
        return;
    }
    cerr<<"Bad call of the function increment counter"<<endl;
    pthread_exit(NULL);
}

void SecureChatServer::checkCounter(int counter, string username, unsigned char* received_counter_msg){
    //counter = 0 -> server, counter = 1 -> user
    __uint128_t received_counter;
    Utility::secure_thread_memcpy((unsigned char*)&received_counter, 0, sizeof(__uint128_t), received_counter_msg, 0, 12, 12);
    memset((unsigned char*)(&received_counter)+12, 0, 4);
    if (counter == 0){
        __uint128_t server_counter_12 = (*users).at(username).server_counter;
        memset((unsigned char*)(&server_counter_12)+12, 0, 4);
        if (server_counter_12 != received_counter || received_counter == (*users).at(username).base_counter){ cerr<<"Bad received server counter"<<endl; pthread_exit(NULL); }
        return;
    }
    if (counter == 1){
        __uint128_t user_counter_12 = (*users).at(username).user_counter;
        memset((unsigned char*)(&user_counter_12)+12, 0, 4);
        if (user_counter_12 != received_counter || received_counter == (*users).at(username).base_counter){ cerr<<"Bad received user counter"<<endl; pthread_exit(NULL); }
        return;
    }
    cerr<<"Bad call of the function check counter"<<endl;
    pthread_exit(NULL);
}

/* ---------------------------------------------------------- *\
|*                                                            *|
|* This function prints the list of users.                    *|
|*                                                            *|
\* ---------------------------------------------------------- */
void SecureChatServer::printUserList(){
    cout<<"Thread "<<gettid()<<": User List"<<endl;
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
    /* ---------------------------------------------------------- *\
    |* Retrive the list of online users.                          *|
    \* ---------------------------------------------------------- */
    vector<User> available = getOnlineUsers();
    char* buf = (char*)malloc(2 + available.size()*(USERNAME_MAX_SIZE+1) + SIGNATURE_SIZE);
    buf[0] = 2;
    if (available.size() > MAX_AVAILABLE_USER_MESSAGE){ buf[1] = MAX_AVAILABLE_USER_MESSAGE; }
    else{ buf[1] = available.size(); }
    unsigned int len = 2;
    /* ---------------------------------------------------------- *\
    |* Format: type=2|num_users|len1|user1|len2|user2|...         *|
    \* ---------------------------------------------------------- */
    for (unsigned int i = 0; i < available.size(); i++){
        if (available[i].username.compare(username) != 0){
            if (len >= AVAILABLE_USER_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; pthread_exit(NULL); }
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
    |* Encrypt and send the message.                              *|
    \* ---------------------------------------------------------- */
    incrementCounter(0, username);
    Utility::printMessage("Base counter: ", (unsigned char*)&(*users).at(username).base_counter, sizeof(__uint128_t));
    unsigned char* ciphertext, *tag, *enc_buf;
    int outlen;
    unsigned int cipherlen;
    unsigned int enc_buf_max_len = 2 + available.size()*(USERNAME_MAX_SIZE+1) + TAG_SIZE + BLOCK_SIZE + GCM_IV_SIZE;
    unsigned int enc_buf_len;
    enc_buf = (unsigned char*)malloc(enc_buf_max_len);
    if (Utility::encryptSessionMessage(len, (*users).at(username).K, (unsigned char*)buf, ciphertext, outlen, cipherlen, (*users).at(username).server_counter, tag, enc_buf, enc_buf_max_len, 0, enc_buf_len) == false){
        cerr<<"Thread "<<gettid()<<"Error in the encryption"<<endl;
        pthread_exit(NULL);
    };
    cout<<"Enc buf len: "<<enc_buf_len<<endl;
    Utility::printMessage("Sent message: ", enc_buf, enc_buf_len);
    if (send(data_socket, enc_buf, enc_buf_len, 0) < 0){
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
    sleep(3);
    char* buf = (char*)malloc(RTT_MAX_SIZE);
    if (!buf){
        cerr<<"Thread "<<gettid()<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }

    unsigned int len = recv(data_socket, (void*)buf, RTT_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the RTT message"<<endl;
        pthread_exit(NULL);
    }

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

    return receiver_username;
}

void SecureChatServer::forwardRTT(string receiver_username, string sender_username){
    int data_socket = (*users).at(receiver_username).socket;
    /* ------------------------------------------------------------------ *\
    |* 3 | sender_username_len(1) | sender_username(MAX=16) | digest(256) *|
    \* ------------------------------------------------------------------ */
    char msg[RTT_MAX_SIZE];
    msg[0] = 3; 
    unsigned int sender_username_len = sender_username.length(); 
    msg[1] = sender_username_len;
    if (sender_username_len + 2 < sender_username_len){ cerr<<"Wrap around"<<endl; exit(1); }
    unsigned int len = sender_username_len + 2;
    if (len >= RTT_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; exit(1); }
    if (2 + (unsigned long)msg < 2){ cerr<<"Wrap around"<<endl; exit(1); }
    memcpy((msg+2), sender_username.c_str(), sender_username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){ cerr<<"Wrap around"<<endl; exit(1); }
    if (len + signature_len < len){ cerr<<"Wrap around"<<endl; exit(1); }
    unsigned int msg_len = len + signature_len;
    if (msg_len >= RTT_MAX_SIZE){ cerr<<"Access out-of-bound"<<endl; exit(1); }
    memcpy(msg + len, signature, signature_len);
    
    unsigned int ret = send(data_socket, msg, msg_len, 0);
    if (ret < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the RTT with error "<<ret<<endl;
		pthread_exit(NULL);
	}
    cout<<"Thread "<<gettid()<<": RTT message sent from "<<sender_username<<" to "<<receiver_username<<endl;
}

string SecureChatServer::receiveResponse(int data_socket, string receiver_username, unsigned int &response){
    /* ------------------------------------------------------------------ *\
    |* 4 | response(1) | username_len(1) | username(MAX=16) | digest(256) *|
    \* ------------------------------------------------------------------ */
    char* buf = (char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){ cerr<<"There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }

    unsigned int len = recv(data_socket, (void*)buf, RESPONSE_MAX_SIZE, 0);
    if (len < 0){ cerr<<"Thread "<<gettid()<<": Error in receiving the Response to RTT message"<<endl; pthread_exit(NULL);}

    checkLogout(data_socket, 0, buf, len, 1, receiver_username, "");
    unsigned int message_type = buf[0];
    if (message_type != 4){ cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl; pthread_exit(NULL);}

    response = buf[1];

    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; pthread_exit(NULL); }
    if (3 + username_len < 3){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = 3 + username_len;
    if (clear_message_len > RESPONSE_MAX_SIZE){ cerr<<"Thread "<<gettid()<<":Access out-of-bound"<<endl; pthread_exit(NULL); }
    string sender_username;
    sender_username.append(buf+3, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){ cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    if (clear_message_len + (unsigned long)buf < clear_message_len){ cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){ cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(receiver_username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error for Response to RTT"<<endl;
        pthread_exit(NULL);
    }

    if ((*users).at(receiver_username).responses.count(sender_username)!=0)
        (*users).at(receiver_username).responses.at(sender_username) = response;
    else
        (*users).at(receiver_username).responses.insert(pair<string, unsigned int>(sender_username, response));

    return sender_username;
}

void SecureChatServer::forwardResponse(string sender_username, string username, unsigned int response){
    int data_socket = (*users).at(sender_username).socket;
    /* ------------------------------------------------------------------ *\
    |* 4 | response(1) | username_len(1) | username(MAX=16) | digest(256) *|
    \* ------------------------------------------------------------------ */
    char msg[RESPONSE_MAX_SIZE];
    msg[0] = 4;
    msg[1] = response;

    unsigned int username_len = sender_username.length();
    msg[2] = username_len;

    if (3 + username_len < 3){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; exit(1); }
    unsigned int len = 3 + username_len;
    if (len > RESPONSE_MAX_SIZE){ cerr<<"Thread "<<gettid()<<":Access out-of-bound"<<endl; exit(1); }
    if (3 + (unsigned long)msg < 3){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; exit(1); }

    memcpy(msg+3, sender_username.c_str(), username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; exit(1); }
    if (len + signature_len < len){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; exit(1); }
    unsigned int msg_len = len + signature_len;
    if (msg_len > RESPONSE_MAX_SIZE){ cerr<<"Thread "<<gettid()<<":Access out-of-bound"<<endl; exit(1); }
    memcpy(msg + len, signature, signature_len);
    
    if (send(data_socket, msg, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }

    cout<<"Thread "<<gettid()<<": Response to RTT sent from "<<username<<" to "<<sender_username<<" with value equal to "<<response<<endl;
}

void SecureChatServer::checkLogout(int data_socket, int other_socket, char* msg, unsigned int buffer_len, unsigned int auth_required, string username, string other_username){
    if(msg[0] != 8)
        return;

    if(msg[1] == 0){
        if(auth_required == 1) 
            return;
        close(data_socket);
        cout<<"Thread "<<gettid()<<":logout completed correctly"<<endl;
        pthread_exit(NULL);
    }
    else{
        unsigned int len = 2;
        unsigned char* logout_nonce = (unsigned char*)malloc(NONCE_SIZE);
        if (!logout_nonce){ cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
        if (len + (unsigned long)msg < len){ cerr<<"Thread "<<"Wrap around"<<endl; pthread_exit(NULL); }
        
        memcpy(logout_nonce, msg+len, NONCE_SIZE);
        len += NONCE_SIZE;

        unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
        if (!signature){ cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
        if (len + (unsigned long)msg < len){ cerr<<"Thread "<<gettid()<<":Wrap around"<<endl; pthread_exit(NULL); }
        memcpy(signature, msg+len, SIGNATURE_SIZE);

        char* clear_message = (char*)malloc(len);
        if (!clear_message){ cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl; pthread_exit(NULL); }
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
                cout<<"Thread "<<gettid()<<":Comunication between "<<username<<" and "<<other_username<<" correctly closed"<<endl;
            } else { cout<<"Thread "<<gettid()<<username<<" logout completed correctly"<<endl; }
            pthread_exit(NULL);
        } else { cerr<<"Thread "<<gettid()<<": logout nonce not corresponding"<<endl;
            return;
        }
    }
}

void SecureChatServer::receive(int data_socket, string username, unsigned int &len, char* buf, const unsigned int max_size){
    if (!buf){
        cerr<<"Thread "<<gettid()<<":There is not more space in memory to allocate a new buffer"<<endl;
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
    if(len < SIGNATURE_SIZE) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    unsigned int clear_message_len = len - SIGNATURE_SIZE;
    if ((unsigned long)buf + clear_message_len < (unsigned long)buf) { cerr<<"Wrap around"<<endl; pthread_exit(NULL); }
    if(Utility::verifyMessage(getUserKey(username), buf, clear_message_len, (unsigned char*)((unsigned long)buf+clear_message_len), SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<":Authentication error while receiving message"<<endl; pthread_exit(NULL);
    }
}

void SecureChatServer::forward(string username, char* msg, unsigned int len){    
    int data_socket = (*users).at(username).socket;
    if (send(data_socket, msg, len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }
}

/* ---------------------------------------------------------- *\
|* to wait the Response message of the receiver before        *|
|* checking the response value in the thread of the sender    *|
\* ---------------------------------------------------------- */
void SecureChatServer::wait(string username){
    unique_lock<mutex> lck((*users).at(username).mtx);
    while(!(*users).at(username).ready)
            (*users).at(username).cv.wait(lck);
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).ready = 0;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
}

/* ------------------------------------------------------------- *\
|* to notify that the Response message has been received         *|
|* before checking the response value in the thread of the sender*|
\* ------------------------------------------------------------- */
void SecureChatServer::notify(string username){
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).ready = 1;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
    (*users).at(username).cv.notify_all();
}

void SecureChatServer::storeK(string username, unsigned char* K){
    (*users).at(username).K = (unsigned char*)malloc(K_SIZE);
    Utility::secure_thread_memcpy((*users).at(username).K, 0, K_SIZE, K, 0, K_SIZE, K_SIZE);
}