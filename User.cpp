#include "User.h"
#include <iostream>
#include "Utility.h"

vector<User>* loadUsers(const char *filename) {
    //TODO: sanitize filename
    ifstream user_file;
    user_file.open(filename);
    if(!user_file.is_open()) {
          return NULL;
    }

    //create the data structure
    vector<User> *user_list = new vector<User>;
    User current;
    char pubkey_path[USERNAME_MAXSIZE+20];
    FILE* fp;
    while(1) {
        //Delete pubkey_path content
        strcpy(pubkey_path, "");

        //Read a new user line
        user_file.getline(current.username, USERNAME_MAXSIZE);
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
        strcat(pubkey_path, current.username);
        strcat(pubkey_path, "_pubkey.pem");

        //Read the pubkey file
        fp = fopen(pubkey_path, "r");

        //Insert the pubkey inside the User structure
        current.pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

        //Close the file
        fclose(fp);

        //Insert the user in the list
        user_list->push_back(current);
    }

}