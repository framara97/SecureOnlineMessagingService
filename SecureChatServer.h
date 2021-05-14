#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <openssl/evp.h>
#include <vector>
#include "User.h"

class SecureChatServer{
    private:
        //Server private key
        static EVP_PKEY* server_prvkey;

        //Server certificate
        static X509* server_certificate;

        //Port and listening IP address, in dotted notation (e.g. 192.168.1.1)
        char address[16];
        uint16_t port;
        int listening_socket;

        //Get the server private key
        static EVP_PKEY* getPrvKey();

        //Get the server certificate
        static X509* getCertificate();

        //List of users
        static vector<User> *users;

        //Setup the socket
        void setupSocket(uint16_t port, const char *addr);

        //Let the main process listen to client requests
        void listenRequests();

    public:
        //Constructor that gets as inputs the address, the port and the user filename.
        SecureChatServer(const char* addr, uint16_t port, const char *user_filename);
};