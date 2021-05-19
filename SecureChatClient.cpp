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

    //Read the client private key
    client_prvkey = getPrvKey();

    //Read the CA certificate
    ca_certificate = getCertificate();

    //Read the CRL
    ca_crl = getCRL();

    //Set the server address and the server port in the class instance
    strcpy(this->server_address, server_addr);
    this->server_port = server_port;

    //Setup the server socket
    setupServerSocket(server_port, server_addr);

    //Receive server certificate
    receiveCertificate();

    //Verify server certificate
    verifyCertificate();

    //Send a message to authenticate to the server
    authenticateUser();
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

void SecureChatClient::receiveCertificate(){
    unsigned char* certificate_buf = (unsigned char*)malloc(CERTIFICATE_MAX_SIZE);

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
    int ret = X509_verify_cert(ctx);
    if(ret != 1) { 
        cerr<<"The certificate of the server is not valid"<<endl;
        exit(1);
    }
    cout<<"The certificate of the server is valid"<<endl;
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

void SecureChatClient::authenticateUser(){

    //Message 0|len|"simeon"|prvk_simeon(digest)
    char msg[BUFFER_SIZE];
    msg[0] = 0; //Type = 0, authentication message
    char username_len = strlen(username); //username length on one byte
    msg[1] = username_len;
    strcpy((msg+2), username);
    int len = username_len + 3;

    uint8_t* signature;
    unsigned int signature_len;
    Utility::signMessage(client_prvkey, msg, len, &signature, &signature_len);

    memcpy(msg+3+username_len, signature, signature_len);
    int msg_len = 3 + username_len + signature_len;
    
    if (send(this->server_socket, msg, msg_len, 0) < 0){
		perror("Error in the sendto of the authentication message.\n");
		exit(1);
	}
}