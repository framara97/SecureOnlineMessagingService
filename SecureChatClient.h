#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include "constants.h"

class SecureChatClient{
    private:

        //Client username
        static char username[USERNAME_MAXSIZE];

        //Client private key
        static EVP_PKEY* client_prvkey;

        //CA certificate
        static X509* ca_certificate;

        //CRL
        static X509_CRL* ca_crl;

        //Port and listening IP address, in dotted notation (e.g. 192.168.1.1)
        char address[16];
        uint16_t port;
        int listening_socket;

        //Port and IP address of the server
        char server_address[16];
        uint16_t server_port;
        int server_socket;

        //Get the server private key
        static EVP_PKEY* getPrvKey();

        //Get the server certificate
        static X509* getCertificate();

        //Get the server CRL
        static X509_CRL* getCRL();

        //Setup the socket
        void setupServerSocket(uint16_t server_port, const char *server_addr);

    public:
        //Constructor that gets the username, the server address and the server port
        SecureChatClient(const char* username, const char *server_addr, uint16_t server_port);
};