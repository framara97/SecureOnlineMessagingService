#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"
#include <openssl/x509.h>

EVP_PKEY* SecureChatServer::server_prvkey = NULL;
X509* SecureChatServer::server_certificate = NULL;
map<string, User>* SecureChatServer::users = NULL;

SecureChatServer::SecureChatServer(const char *addr, int port, const char *user_filename) {

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
    printf("%s\n", path);
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
		cerr<<"Thread "<<gettid()<<": Error in the bind"<<endl;
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
    char* username = receiveAuthentication(data_socket);

    //Change user status to active
    int status = 1;
    changeUserStatus(username, status);
    printUserList();

    //Send the list of available users
    sendAvailableUsers(data_socket, username);

    //Server's thread receive the RTT message
    receiveRTT(data_socket, username);

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

char* SecureChatServer::receiveAuthentication(int process_socket){
    char* authentication_buf = (char*)malloc(AUTHENTICATION_MAX_SIZE);
    int authentication_len = recv(process_socket, (void*)authentication_buf, AUTHENTICATION_MAX_SIZE, 0);
    if (authentication_len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the authentication message"<<endl;
        exit(1);
    }
    cout<<"Thread "<<gettid()<<": Authentication message received"<<endl;

    printf("%d\n", authentication_len);
    for (int i=0; i<authentication_len; i++){
        printf("%02hhx", authentication_buf[i]);
    }
    printf("\n");

    int message_type = authentication_buf[0];
    if (message_type != 0){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'authentication type'."<<endl;
        exit(1);
    }
    int username_len = authentication_buf[1];
    if (username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Username length is over the upper bound."<<endl;
    }
    char* username = (char*)malloc(username_len);
    memcpy(username, authentication_buf+2, username_len+1);
    printf("%s\n", username);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    memcpy(signature, authentication_buf+3+username_len, SIGNATURE_SIZE);

    int clear_message_len = username_len+3;
    char* clear_message = (char*)malloc(clear_message_len);
    memcpy(clear_message, authentication_buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey((char*)username);

    int ret = Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE);
    if(ret != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication is ok"<<endl;

    return username;
}

void SecureChatServer::changeUserStatus(char* username, int status){
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).status = status;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
}

void SecureChatServer::printUserList(){
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        it->second.printUser();
    }
}

vector<User> SecureChatServer::getOnlineUsers(){
    vector<User> v;
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        if (it->second.status == 1){
            v.push_back(it->second);
        }
    }
    return v;
}

void SecureChatServer::sendAvailableUsers(int data_socket, char* username){
    char buf[AVAILABLE_USER_MAX_SIZE];
    buf[0] = 1;
    vector<User> available = getOnlineUsers();
    if (available.size() > MAX_AVAILABLE_USER_MESSAGE){
        buf[1] = MAX_AVAILABLE_USER_MESSAGE;
    }
    else{
        buf[1] = available.size();
    }
    int len = 2;
    // |1|2|5|alice\0|3|bob\0| -> 14
    for (int i = 0; i < available.size(); i++){
        //if (strcmp(available[i].username, username)!=0){
            buf[len] = strlen(available[i].username);
            strcpy(buf+len+1, available[i].username);
            len += 2 + strlen(available[i].username);
        //}
    }

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, buf, len, &signature, &signature_len);

    memcpy(buf+len, signature, signature_len);
    int msg_len = len + signature_len;
    
    if (send(data_socket, buf, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<"Error in the sendto of the available user list"<<endl;
		exit(1);
	}

}

void SecureChatServer::receiveRTT(int data_socket, char* username){
    char* buf = (char*)malloc(RTT_MAX_SIZE);
    int len = recv(data_socket, (void*)buf, RTT_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the RTT message"<<endl;
        exit(1);
    }
    cout<<"Thread "<<gettid()<<": RTT message received"<<endl;

    printf("%d\n", len);
    for (int i=0; i<len; i++){
        printf("%02hhx", buf[i]);
    }
    printf("\n");

    int message_type = buf[0];
    if (message_type != 2){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'RTT type'."<<endl;
        exit(1);
    }
    int receiver_username_len = buf[1];
    if (receiver_username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Receiver Username length is over the upper bound."<<endl;
    }
    char* receiver_username = (char*)malloc(receiver_username_len);
    memcpy(receiver_username, buf+2, receiver_username_len+1);
    printf("%s\n", receiver_username);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    memcpy(signature, buf + 3 + receiver_username_len, SIGNATURE_SIZE);

    int clear_message_len = receiver_username_len + 3;
    char* clear_message = (char*)malloc(clear_message_len);
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey((char*)username);

    int ret = Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE);
    if(ret != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication is ok"<<endl;

    //TODO gestire la RTT inviandola al receiver
}