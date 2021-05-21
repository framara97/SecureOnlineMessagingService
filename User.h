#include <fstream>
#include <vector>
#include <map>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include "constants.h"
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

    User(const User &user);

    User();

    User(string username, EVP_PKEY* pubkey, int socket, int status);

    void printUser();

};

/*Load all registered users from a file into a vector. This will be called when the server is created.
Return NULL in case of failure. */
map<string, User>* loadUsers(const char *filename);