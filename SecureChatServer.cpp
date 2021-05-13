#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include "Utility.h"

SecureChatServer::SecureChatServer(const char *addr, uint16_t port, const char *user_filename) {
    /*assumes not tainted parameters. (parameters are sanitized in main function)*/

    //Read the server private key
    server_prvkey = getPrvKey();

    //Set the server address and the server port in the class instance
    strcpy(this->address, addr);
    this->port = port;

    //Set the user list in the class instance
    this->users = loadUsers(user_filename);
    launch();
}

EVP_PKEY* SecureChatServer::getPrvKey() {
    server_prvkey = Utility::readPrvKey("./server/server_key.pem", NULL);
    return server_prvkey;
}