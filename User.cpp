#include "User.h"
#include <iostream>

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
    char pubkey_path[USERNAME_MAX_SIZE+20]; // ./server/username_pubkey.pem
    FILE* fp;
    EVP_PKEY* read_pubkey = NULL;
    string username;
    while(1) {
        //Delete pubkey_path content
        strcpy(pubkey_path, "");

        //Read a new user line
        getline(user_file, username);
        //Check if the line exists
        if(user_file.fail() && user_file.eof()) { //in this case there are no more users to read
            return user_list;
        }
        else if(user_file.fail()) { //in this case an error occurred
            delete user_list;
            return NULL;
        }

        if (username.length() > USERNAME_MAX_SIZE){ //the current read username is too long 
            continue;
        }

        //Retrieve the user public key
        strcat(pubkey_path, "./server/");
        strcat(pubkey_path, username.c_str());
        strcat(pubkey_path, "_pubkey.pem");

        //Read the pubkey file
        fp = fopen(pubkey_path, "r");

        //Insert the pubkey inside the User structure
        read_pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

        //Close the file
        fclose(fp);

        current = new User(username, read_pubkey, 0, 0);

        //Insert the user in the list
        user_list->insert( pair<string, User>(username, *current) );
    }

}

User::User(const User &user){
    this->pubkey = user.pubkey;
    this->socket = user.socket;
    this->status = user.status;
    this->username = user.username;
    if (pthread_mutex_init(&this->user_mutex, NULL) != 0){
        cerr<<"Error in initializing the mutex"<<endl;
    };
}

User::User(string username, EVP_PKEY* pubkey, int socket, unsigned int status){
    this->pubkey = pubkey;
    this->socket = socket;
    this->status = status;
    this->username = username;
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