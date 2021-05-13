#include "SecureChatServer.h"
#include "SecureChatClient.h"
#include "cstring"
#include <iostream>

using namespace std;

int main(int argc, char** argv){

    if (argc < 2) {
        cout << "Pass 1 to start the server, pass 2 o 3 to start a user." << endl;
        return 0;
    }

    if(strcmp(argv[1], "1") == 0) {
        SecureChatServer server("127.0.0.1", 9000, "userFile");
    }

    if(strcmp(argv[1], "2") == 0)
        SecureChatClient client("Simeon","127.0.0.1",9000);
    if(strcmp(argv[1], "3") == 0)
        SecureChatClient client("Mbala","127.0.0.1",9000);
    return 0;
}