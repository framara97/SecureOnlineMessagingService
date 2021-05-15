#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"
#include <openssl/x509.h>

EVP_PKEY* SecureChatServer::server_prvkey = NULL;
X509* SecureChatServer::server_certificate = NULL;
vector<User>* SecureChatServer::users = NULL;

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
	cout<<"Proc. "<<getpid()<<": Socket created to receive client requests."<<endl;

	if (bind(this->listening_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Error in the bind"<<endl;
		exit(1);
	}

    if (listen(this->listening_socket, 10)){
        cerr<<"Error in the listen"<<endl;
        exit(1);
    }

	cout<<"Proc. "<<getpid()<<": Socket associated through bind."<<endl;
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
            cerr<<"Error in the accept"<<endl;
            exit(1);
        }
        cout<<"Proc. "<<getpid()<<": Request received by a client with address "<<inet_ntoa(client_addr.sin_addr)<<" and port "<<ntohs(client_addr.sin_port)<<endl;
        pid = fork();

        if (pid < 0){
            cerr<<"Error while creating a new child process"<<endl;
            exit(1);
        }

        if (pid == 0){
            //Child process
            sendCertificate(new_socket, &client_addr, addrlen);

            exit(0);
        }
    }
}

void SecureChatServer::sendCertificate(int process_socket, struct sockaddr_in* client_addr, int len){
    uint8_t msg[BUFFER_SIZE];
    memset(msg, 0, BUFFER_SIZE);
	int msg_len;

    //TODO: Mettere il certificato nel buffer
	
	if (send(process_socket, msg, msg_len, 0) < 0){
		perror("Error in the sendto of the message containing the certificate.\n");
		exit(1);
	}
	return;
}