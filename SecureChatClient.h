#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include "Utility.h"

class SecureChatClient{
    private:

        //Client username
        static string username;

        //Client choice
        static unsigned int choice;

        //Client private key
        static EVP_PKEY* client_prvkey;

        //CA certificate
        static X509* ca_certificate;

        //CRL
        static X509_CRL* ca_crl;

        //Port and IP address of the server
        struct sockaddr_in server_addr;
        char server_address[MAX_ADDRESS_SIZE];
        unsigned short int server_port;
        int server_socket;

        //Server certificate
        X509* server_certificate;

        //Server Public key
        EVP_PKEY* server_pubkey;

        //Get the server private key
        static EVP_PKEY* getPrvKey();

        //Get the server certificate
        static X509* getCertificate();

        //Get the server CRL
        static X509_CRL* getCRL();

        //Setup the server address into the sockaddr_in structure
        void setupServerAddress(unsigned short int server_port, const char *server_addr);

        //Setup the socket
        void setupSocket();

        //Setup the server socket
        void setupServerSocket(unsigned short int server_port, const char *server_addr);

        //Receive server certificate
        void receiveCertificate();

        //Receive user public key
        EVP_PKEY* receiveUserPubKey(string username);

        //Verify server certificate
        void verifyCertificate();

        //Authenticate user
        void authenticateUser(unsigned int choice);

        //Receive the list of available users
        string receiveAvailableUsers();

        //Send request to talk to the selected user
        void sendRTT(string selected_user);

        //Wait for a message from another user
        string waitForRTT();

        //Send response to RTT
        void sendResponse(string sender_username, unsigned int response);

        //Wait for response to RTT
        unsigned int waitForResponse();

    public:
        //Constructor that gets the username, the server address and the server port
        SecureChatClient(string username, const char *server_addr, unsigned short int server_port);
};