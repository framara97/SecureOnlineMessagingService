#include <iostream>

#include "SecureChatServer.h"
#include "cstring"
#include <string>

using namespace std;

bool isValidIpAddress(char *ipAddress){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main( int argc, char** argv) {

    if (argc < 4) {
        cout << "usage: ./server $ip_address $port $userFile" << endl;
        return 0;
    }

    if(!isValidIpAddress(argv[1])) {
        cout<<"please insert a valid ip address"<<endl;
        exit(1);
    }

    int port;
    try {
        port = stoi(argv[2]);
    } catch (exception &err){
        cout<<"please insert a valid port number"<<endl;
        exit(1);
    }

    if(port <= 0 || port >= 65536) {
        cout<<"Please insert a correct port number"<<endl;
        exit(1);
    }

    string userFile = argv[3];
    /*if(!Utility::checkWhitelist(userFile)) {
        cout<<"Insert a correct user file name format"<<endl;
        exit(1);
    }*/

    SecureChatServer server(argv[1], port, argv[3]);
    return 0;
}