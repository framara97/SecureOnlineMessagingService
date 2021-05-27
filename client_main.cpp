#include <iostream>
#include "SecureChatClient.h"

using namespace std;

bool isValidIpAddress(char *ipAddress){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main( int argc, char** argv) {

    if (argc < 4) {
        cout << "usage: ./client username serverIP serverPort"<< endl;
        return 0;
    }
    if(!isValidIpAddress(argv[2])){
        cout<<"The ip address of the server must be valid.."<<endl;
        return 0;
    }
    int serverPort;
    try{
        serverPort = stoi(argv[3]);
    }catch (exception &err){
        cout<<"The server port must be a number"<<endl;
        return 0;
    }
    if(serverPort<=0 || serverPort>=65536){
        cout<<"The server port must be positive and between 0 and 65536"<<endl;
        return 0;
    }
    SecureChatClient client(argv[1],argv[2],stoi(argv[3]));

    return 0;
}