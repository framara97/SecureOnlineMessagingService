#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"
#include <openssl/x509.h>

EVP_PKEY* SecureChatServer::server_prvkey = NULL;
X509* SecureChatServer::server_certificate = NULL;
map<string, User>* SecureChatServer::users = NULL;

SecureChatServer::SecureChatServer(const char *addr, uint16_t port, const char *user_filename) {
    /*assumes not tainted parameters. (parameters are sanitized in main function)*/

    //Read the server private key
    server_prvkey = getPrvKey();

    //Read the server certificate
    server_certificate = getCertificate();

    //Set the server address and the server port in the class instance
    strcpy(this->address, addr);
    this->port = port;

    //Set the user list in the class instance
    this->users = loadUsers(user_filename);

    //Setup the server socket
    setupSocket();

    //Let the server listen to client requests
    listenRequests();

}

EVP_PKEY* SecureChatServer::getPrvKey() {
    server_prvkey = Utility::readPrvKey("./server/server_key.pem", NULL);
    return server_prvkey;
}

EVP_PKEY* SecureChatServer::getUserKey(char* username) {
    char path[BUFFER_SIZE] = "./server/";
    strcat(path, username);
    strcat(path, "_pubkey.pem");
    EVP_PKEY* username_pubkey = Utility::readPubKey(path, NULL);
    return username_pubkey;
}

X509* SecureChatServer::getCertificate(){
    server_certificate = Utility::readCertificate("./server/server_cert.pem");
    return server_certificate;
}

void SecureChatServer::setupSocket(){
    this->listening_socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&this->server_addr, 0, sizeof(this->server_addr));
	this->server_addr.sin_family = AF_INET;
	this->server_addr.sin_port = htons(this->port);
    inet_pton(AF_INET, this->address, &this->server_addr.sin_addr);
	cout<<"Thread "<<gettid()<<": Socket created to receive client requests."<<endl;

	if (bind(this->listening_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Thread "<<gettid()<<"Error in the bind"<<endl;
		exit(1);
	}

    if (listen(this->listening_socket, 10)){
        cerr<<"Thread "<<gettid()<<": Error in the listen"<<endl;
        exit(1);
    }

	cout<<"Thread "<<gettid()<<": Socket associated through bind."<<endl;
}

void SecureChatServer::listenRequests(){
    pid_t pid;
    int new_socket;
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t addrlen = sizeof(struct sockaddr_in);
    addrlen = sizeof(client_addr);

    while(1){
        
        //Waiting for a client request
        new_socket = accept(this->listening_socket, (struct sockaddr*)&client_addr, &addrlen);
        if (new_socket < 0){
            cerr<<"Thread "<<gettid()<<"Error in the accept"<<endl;
            exit(1);
        }
        cout<<"Thread "<<gettid()<<": Request received by a client with address "<<inet_ntoa(client_addr.sin_addr)<<" and port "<<ntohs(client_addr.sin_port)<<endl;

        //Create a new thread to handle the new connection
        thread handler (&SecureChatServer::handleConnection, this, new_socket, client_addr);
        handler.detach();
    }
}

void SecureChatServer::handleConnection(int data_socket, sockaddr_in client_address){
    //Send certificate to the new user
    sendCertificate(data_socket);
    cout<<"Thread "<<gettid()<<": Certificate sent"<<endl;

    //Receive authentication from the user
    unsigned char* username = receiveAuthentication(data_socket);

    //Change user status to active
    int status = 1;
    changeUserStatus(username, status);

    pthread_exit(NULL);
}

void SecureChatServer::sendCertificate(int process_socket){

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, server_certificate);
    char* certificate_buf = NULL;
    long certificate_size = BIO_get_mem_data(mbio, &certificate_buf);
	
	if (send(process_socket, certificate_buf, certificate_size, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the sendto of the message containing the certificate."<<endl;
		exit(1);
	}

    BIO_free(mbio);
	return;
}

unsigned char* SecureChatServer::receiveAuthentication(int process_socket){
    unsigned char* authentication_buf = (unsigned char*)malloc(AUTHENTICATION_MAX_SIZE);
    int authentication_len = recv(process_socket, (void*)authentication_buf, AUTHENTICATION_MAX_SIZE, 0);
    if (authentication_len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the authentication message"<<endl;
        exit(1);
    }
    cout<<"Thread "<<gettid()<<": Authentication message received"<<endl;

    int message_type = authentication_buf[0];
    if (message_type != 0){
        cerr<<"Proc. "<<getpid()<<": Message type is not corresponding to 'authentication type'."<<endl;
        exit(1);
    }
    int username_len = authentication_buf[1];
    unsigned char* username = (unsigned char*)malloc(username_len);
    memcpy(username, authentication_buf+2, username_len);

    int signature_len = authentication_len-3-username_len;
    unsigned char* signature = (unsigned char*)malloc(signature_len);
    memcpy(signature, authentication_buf+3+username_len, signature_len);

    int clear_message_len = username_len+3;
    unsigned char* clear_message = (unsigned char*)malloc(clear_message_len);
    memcpy(clear_message, authentication_buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey((char*)username);

    int ret = Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, signature_len);
    if(ret != 1) { 
        cerr<<"Thread "<<gettid()<<"Authentication error"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication is ok"<<endl;
    changeUserStatus(reinterpret_cast<char*>(username), 1);
    return username;
}

void SecureChatServer::changeUserStatus(char* username, int status){
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).status = status;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
    printUserList();
}

void SecureChatServer::printUserList(){
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        it->second.printUser();
    }
}