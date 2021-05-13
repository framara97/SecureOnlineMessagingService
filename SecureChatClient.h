#include <sys/types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>

class SecureChatClient{
    private:

    public:
        //Constructor that gets the username, the server address and the server port
        SecureChatClient(const char* username, const char *server_addr, uint16_t server_port);
};