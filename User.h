#include <fstream>
#include <vector>
#include <map>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include "Utility.h"
#include <openssl/evp.h>

using namespace std;

struct User {
    //Username of the user
    string username;

    //Socket assigned to the user
    int socket;

    //Status of the user
    //1: online
    //0: offline
    unsigned int status;

    //security fields
    EVP_PKEY* pubkey;

    //Mutex used to avoid multiple simultaneous accesses
    pthread_mutex_t user_mutex;

    //This variable is used to communicate between the thread of the sender and the thread of the receiver during the protocol
    condition_variable cv;
    bool ready;
    mutex mtx;
    map<string, int> responses;

    User(const User &user);

    User();

    User(string username, EVP_PKEY* pubkey, int socket, unsigned int status);

    void printUser();

};

/*Load all registered users from a file into a vector. This will be called when the server is created.
Return NULL in case of failure. */
map<string, User>* loadUsers(const char *filename);