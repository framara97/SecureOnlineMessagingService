#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include <openssl/evp.h>

class SecureChatServer{
    private:
        //Server private key
        static EVP_PKEY* server_prvkey;

        //Port and listening IP address, in dotted notation (e.g. 192.168.1.1)
        char address[16];
        uint16_t port;
        int listening_socket;

        //Get the server private key
        static EVP_PKEY* getPrvKey();

    public:
        //Constructor that gets as inputs the address, the port and the user filename.
        SecureChatServer(const char* addr, uint16_t port, const char *user_filename);
};