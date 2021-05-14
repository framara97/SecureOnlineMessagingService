#include "SecureChatClient.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"

char SecureChatClient::username[USERNAME_MAXSIZE] = "";
EVP_PKEY* SecureChatClient::client_prvkey = NULL;
X509* SecureChatClient::ca_certificate = NULL;
X509_CRL* SecureChatClient::ca_crl = NULL;

SecureChatClient::SecureChatClient(const char* username, const char *server_addr, uint16_t server_port) {
    /*assumes not tainted parameters. (parameters are sanitized in main function)*/

    //Read the server private key
    client_prvkey = getPrvKey();

    //Read the server certificate
    ca_certificate = getCertificate();

    //Read the CRL
    ca_crl = getCRL();

    //Set the server address and the server port in the class instance
    strcpy(this->server_address, server_addr);
    this->server_port = server_port;

    //Setup the server socket
    setupServerSocket(server_port, server_addr);

    
}

EVP_PKEY* SecureChatClient::getPrvKey() {
    char path[BUFFER_SIZE] = "";
    strcat(path, "./client/");
    strcat(path, username);
    strcat(path, "/");
    strcat(path, username);
    strcat(path, "_key_password.pem");
    client_prvkey = Utility::readPrvKey(path, NULL);
    return client_prvkey;
}

X509* SecureChatClient::getCertificate(){
    char path[BUFFER_SIZE] = "";
    strcat(path, "./client/");
    strcat(path, username);
    strcat(path, "/ca_cert.pem");
    ca_certificate = Utility::readCertificate(path);
    return ca_certificate;
}

X509_CRL* SecureChatClient::getCRL(){
    char path[BUFFER_SIZE] = "";
    strcat(path, "./client/");
    strcat(path, username);
    strcat(path, "/ca_crl.pem");
    ca_crl = Utility::readCRL(path);
    return ca_crl;
}

void SecureChatClient::setupServerSocket(uint16_t server_port, const char *addr){
	struct sockaddr_in server_addr;
    this->server_socket = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, addr, &server_addr.sin_addr);

	if (bind(this->server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		cerr<<"Error in the bind"<<endl;
		exit(1);
	}
}