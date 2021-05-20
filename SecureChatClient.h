#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include "constants.h"
#include "Utility.h"

class SecureChatClient{
    private:

        //Client username
        static char username[USERNAME_MAX_SIZE];

        //Client private key
        static EVP_PKEY* client_prvkey;

        //CA certificate
        static X509* ca_certificate;

        //CRL
        static X509_CRL* ca_crl;

        //Port and IP address of the server
        struct sockaddr_in server_addr;
        char server_address[16];
        uint16_t server_port;
        int server_socket;

        //Server certificate
        X509* server_certificate;

        //Get the server private key
        static EVP_PKEY* getPrvKey();

        //Get the server certificate
        static X509* getCertificate();

        //Get the server CRL
        static X509_CRL* getCRL();

        //Setup the server address into the sockaddr_in structure
        void setupServerAddress(uint16_t server_port, const char *server_addr);

        //Setup the socket
        void setupSocket();

        //Setup the server socket
        void setupServerSocket(uint16_t server_port, const char *server_addr);

        //Receive server certificate
        void receiveCertificate();

        //Verify server certificate
        void verifyCertificate();

        //Authenticate user
        void authenticateUser();

        //Receive the list of available users
        void receiveAvailableUsers();

    public:
        //Constructor that gets the username, the server address and the server port
        SecureChatClient(const char* username, const char *server_addr, uint16_t server_port);
};