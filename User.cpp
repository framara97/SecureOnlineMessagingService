#include "User.h"
#include <iostream>
#include "Utility.h"

using namespace std;

map<string, User>* loadUsers(const char *filename) {
    //TODO: sanitize filename
    ifstream user_file;
    user_file.open(filename);
    if(!user_file.is_open()) {
          return NULL;
    }

    //create the data structure
    map<string, User> *user_list = new map<string, User>;
    User* current;
    char pubkey_path[USERNAME_MAXSIZE+20];
    FILE* fp;
    EVP_PKEY* read_pubkey = NULL;
    char username[USERNAME_MAXSIZE];
    while(1) {
        //Delete pubkey_path content
        strcpy(pubkey_path, "");

        //Read a new user line
        user_file.getline(username, USERNAME_MAXSIZE);
        //Check if the line exists
        if(user_file.fail() && user_file.eof()) { //in this case there are no more users to read
            return user_list;
        }
        else if(user_file.fail()) { //in this case an error occurred
            delete user_list;
            return NULL;
        }

        //Retrieve the user public key
        strcat(pubkey_path, "./server/");
        strcat(pubkey_path, username);
        strcat(pubkey_path, "_pubkey.pem");

        //Read the pubkey file
        fp = fopen(pubkey_path, "r");

        //Insert the pubkey inside the User structure
        read_pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

        //Close the file
        fclose(fp);

        current = new User(username, read_pubkey, 0, 0);

        //Insert the user in the list
        user_list->insert( pair<string, User>((string)username, *current) );
    }

}

User::User(const User &user){
    this->pubkey = user.pubkey;
    this->socket = user.socket;
    this->status = user.status;
    strcpy(this->username, user.username);
    if (pthread_mutex_init(&this->user_mutex, NULL) != 0){
        cerr<<"Error in initializing the mutex"<<endl;
    };
}

User::User(const char* username, EVP_PKEY* pubkey, int socket, int status){
    this->pubkey = pubkey;
    this->socket = socket;
    this->status = status;
    strcpy(this->username, username);
    if (pthread_mutex_init(&this->user_mutex, NULL) != 0){
        cerr<<"Error in initializing the mutex"<<endl;
    };
}

User::User(){
    if (pthread_mutex_init(&this->user_mutex, NULL) != 0){
        cerr<<"Error in initializing the mutex"<<endl;
    };
}

void User::printUser(){
    cout<<"Username: "<<this->username<<endl;
    cout<<"Pubkey: "<<this->pubkey<<endl;
    cout<<"Status: "<<this->status<<endl;
}