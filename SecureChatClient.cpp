#include "SecureChatClient.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"

char SecureChatClient::username[USERNAME_MAXSIZE] = "";
EVP_PKEY* SecureChatClient::client_prvkey = NULL;
X509* SecureChatClient::ca_certificate = NULL;
X509_CRL* SecureChatClient::ca_crl = NULL;

SecureChatClient::SecureChatClient(const char* client_username, const char *server_addr, uint16_t server_port) {
    /*assumes not tainted parameters. (parameters are sanitized in main function)*/

    //Set username
    strcpy(username, client_username);

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

    //Message "simeon"|prvk_simeon(digest)
    uint8_t msg[BUFFER_SIZE];
    msg[0] = 0; //Type = 0, request message
    uint8_t username_len = strlen(username);
    msg[1] = username_len;
    strcpy((char*)(msg+2), username);
    
    uint8_t* signature;
    unsigned int signature_len;
    signature = (uint8_t*)malloc(EVP_PKEY_size(client_prvkey));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, (uint8_t*)msg, sizeof(msg));
    EVP_SignFinal(ctx, signature, &signature_len, client_prvkey);
    EVP_MD_CTX_free(ctx);

    strcpy((char*)msg+3+username_len, (char*)signature);
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

void SecureChatClient::setupServerAddress(uint16_t port, const char *addr){
    memset(&(this->server_addr), 0, sizeof(this->server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	inet_pton(AF_INET, addr, &(this->server_addr.sin_addr));
}


void SecureChatClient::setupServerSocket(uint16_t server_port, const char *addr){
    this->server_socket = socket(AF_INET, SOCK_STREAM, 0);
	setupServerAddress(server_port, addr);

	if (connect(this->server_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Error in the connect"<<endl;
		exit(1);
	}
    cout<<"Connected to the server"<<endl;
}