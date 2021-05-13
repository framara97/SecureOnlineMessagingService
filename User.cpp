#include "User.h"

vector<User>* loadUsers(const char *filename) {
    //TODO: sanitize filename
    ifstream user_file;
    user_file.open(filename);
    if(!user_file.is_open()) {
          return NULL;
    }

    //create the data structure
    vector<User> *user_list = new vector<User>;
    while(1) {
        User current;
        for(int i = 0; i < 2; ++i) {
            switch(i) {
                case 0:
                    user_file.getline(current.username, USERNAME_MAXSIZE);
                    if(user_file.fail() && user_file.eof()) { //in this case there are no more users to read
                        return user_list;
                    }
                    else if(user_file.fail()) { //in this case an error occurred
                        delete user_list;
                        return NULL;
                    }
                    break;
                case 1:
                    //TODO: save public key
                    break;
                default:
                    break;
            }
        }
        user_list->push_back(current);
    }

}