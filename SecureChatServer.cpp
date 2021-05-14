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
    setupSocket(port, addr);

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

void SecureChatServer::setupSocket(uint16_t port, const char *addr){
	struct sockaddr_in server_addr;
    this->listening_socket = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
    inet_pton(AF_INET, addr, &server_addr.sin_addr);
	cout<<"Proc. "<<getpid()<<": Socket created to receive client requests."<<endl;

	if (bind(this->listening_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		cerr<<"Error in the bind"<<endl;
		exit(1);
	}
	cout<<"Proc. "<<getpid()<<": Socket associated through bind."<<endl;
}

void SecureChatServer::listenRequests(){
    pid_t pid;
    uint8_t buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t addrlen = sizeof(struct sockaddr_in);
    addrlen = sizeof(client_addr);

    while(1){
        //Waiting for a client request
        if (recvfrom(this->listening_socket, buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&client_addr, &addrlen) < 0){
            cerr<<"Error in the recvfrom"<<endl;
            exit(1);
        }
        cout<<"Proc. "<<getpid()<<": Request received by a client with address "<<inet_ntoa(client_addr.sin_addr)<<" and port "<<ntohs(client_addr.sin_port)<<endl;
        //pid = fork();
    }
}