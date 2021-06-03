#include "SecureChatServer.h"
#include <cstring>
#include <iostream>
#include <thread>
#include <openssl/x509.h>

EVP_PKEY* SecureChatServer::server_prvkey = NULL;
X509* SecureChatServer::server_certificate = NULL;
map<string, User>* SecureChatServer::users = NULL;

SecureChatServer::SecureChatServer(const char *addr, unsigned short int port, const char *user_filename) {

    //Read the server private key
    server_prvkey = getPrvKey();

    //Read the server certificate
    server_certificate = getCertificate();

    //Set the server address and the server port in the class instance
    strncpy(this->address, addr, MAX_ADDRESS_SIZE-1);
    this->address[MAX_ADDRESS_SIZE-1] = '\0';
    this->port = port;

    //Set the user list in the class instance
    this->users = loadUsers(user_filename);

    //Setup the server socket
    setupSocket();

    //Let the server listen to client requests
    listenRequests();
}

EVP_PKEY* SecureChatServer::getPrvKey() {
    server_prvkey = Utility::readPrvKey("./server/server_key.pem", NULL);
    return server_prvkey;
}

EVP_PKEY* SecureChatServer::getUserKey(string username) {
    string path = "./server/" + username + "_pubkey.pem";
    EVP_PKEY* username_pubkey = Utility::readPubKey(path.c_str(), NULL);
    return username_pubkey;
}

X509* SecureChatServer::getCertificate(){
    server_certificate = Utility::readCertificate("./server/server_cert.pem");
    return server_certificate;
}

void SecureChatServer::setupSocket(){
    this->listening_socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&this->server_addr, 0, sizeof(this->server_addr));
	this->server_addr.sin_family = AF_INET;
	this->server_addr.sin_port = htons(this->port);
    inet_pton(AF_INET, this->address, &this->server_addr.sin_addr);
	cout<<"Thread "<<gettid()<<": Socket created to receive client requests."<<endl;

	if (bind(this->listening_socket, (struct sockaddr*)&this->server_addr, sizeof(this->server_addr)) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the bind"<<endl;
		exit(1);
	}

    if (listen(this->listening_socket, 10)){
        cerr<<"Thread "<<gettid()<<": Error in the listen"<<endl;
        exit(1);
    }

	cout<<"Thread "<<gettid()<<": Socket associated through bind."<<endl;
}

void SecureChatServer::listenRequests(){
    pid_t pid;
    int new_socket;
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t addrlen = sizeof(struct sockaddr_in);
    addrlen = sizeof(client_addr);

    while(1){
        
        //Waiting for a client request
        new_socket = accept(this->listening_socket, (struct sockaddr*)&client_addr, &addrlen);
        if (new_socket < 0){
            cerr<<"Thread "<<gettid()<<"Error in the accept"<<endl;
            exit(1);
        }
        cout<<"Thread "<<gettid()<<": Request received by a client with address "<<inet_ntoa(client_addr.sin_addr)<<" and port "<<ntohs(client_addr.sin_port)<<endl;

        //Create a new thread to handle the new connection
        thread handler (&SecureChatServer::handleConnection, this, new_socket, client_addr);
        handler.detach();
    }
}

void SecureChatServer::handleConnection(int data_socket, sockaddr_in client_address){
    //Send certificate to the new user
    sendCertificate(data_socket);
    cout<<"Thread "<<gettid()<<": Certificate sent"<<endl;

    unsigned int status;
    //Receive authentication from the user
    string username = receiveAuthentication(data_socket, status);

    //Change user status to 1 if the user is available to receive a message
    changeUserStatus(username, status, data_socket);

    printUserList();

    if(status == 0){//user wants to send message
        //Send the list of users that are available to receive
        sendAvailableUsers(data_socket, username);
        
        //Server's thread receive the RTT message
        string receiver_username = receiveRTT(data_socket, username);

        //Server forwards the RTT to the final receiver
        forwardRTT(receiver_username, username);

        //wait on the condition variable of the receiver
        unique_lock<mutex> lck((*users).at(receiver_username).mtx);

        while(!(*users).at(receiver_username).ready)
            (*users).at(receiver_username).cv.wait(lck);

        cout<<"Th. Antetokoumpo"<<endl;

        //pthread_mutex_lock(&(*users).at(receiver_username).user_mutex);
        cout<<"Bonaccorsi: "<<(*users).at(receiver_username).responses.at(username)<<endl;
        if((*users).at(receiver_username).responses.at(username) == 1) {
            //Server sends public keys to the user
            cout<<"Pola"<<endl;
            sendUserPubKey(receiver_username, data_socket);
        }
        //pthread_mutex_unlock(&(*users).at(receiver_username).user_mutex);

        char msg[GENERAL_MSG_SIZE];
        unsigned int len;

        receive(data_socket, username, len, msg);
        cout<<"Vaglini: "<<endl;
        for (int i = 0; i < 5; i++){
            printf("%02hhx", msg[i]);
        }
        cout<<endl;
        msg[len] = '\0';
        forward(receiver_username, msg, len);
    }
    if (status == 1){ //user wants to receive a message
        //Server waits for the response (accept or refuse) from the final receiver
        unsigned int response;
        string sender_username = receiveResponse(data_socket, username, response);

        //Server forwards the response to the sender
        forwardResponse(sender_username, response);

        //Frees the other thread that is handling the sender
        unique_lock<mutex> lck((*users).at(username).mtx);
        pthread_mutex_lock(&(*users).at(username).user_mutex);
        (*users).at(username).ready = 1;
        pthread_mutex_unlock(&(*users).at(username).user_mutex);
        (*users).at(username).cv.notify_all();

        char msg[GENERAL_MSG_SIZE];
        unsigned int len;
        
        if (response == 1){

            sendUserPubKey(sender_username, data_socket);
            //strncpy(msg, receive(data_socket, username, len), len);
            //msg[len] = '\0';
            //forward(sender_username, msg, len);
        }
    }

    pthread_exit(NULL);
}

void SecureChatServer::sendCertificate(int process_socket){

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, server_certificate);
    char* certificate_buf = NULL;
    long certificate_size = BIO_get_mem_data(mbio, &certificate_buf);
	
	if (send(process_socket, certificate_buf, certificate_size, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the sendto of the message containing the certificate."<<endl;
		pthread_exit(NULL);
	}

    BIO_free(mbio);
	return;
}

void SecureChatServer::sendUserPubKey(string username, int data_socket){

    char buf[PUBKEY_MSG_SIZE];
    char* pubkey_buf = NULL;
    buf[0] = 5;

    EVP_PKEY* pubkey = getUserKey(username);

    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, pubkey);

    long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
    if (1 + PUBKEY_SIZE < 1){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int len = 1 + pubkey_size;
    if (1 + pubkey_size > PUBKEY_MSG_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        pthread_exit(NULL);
    }
    memcpy(buf+1, pubkey_buf, pubkey_size);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, buf, len, &signature, &signature_len);

    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    if (len + signature_len > PUBKEY_MSG_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        pthread_exit(NULL);
    }
    if (len + (unsigned long)buf < len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int msg_len = len + signature_len;
    memcpy(buf+len, signature, signature_len);
	
	if (send(data_socket, buf, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the sendto of the message containing the public key to "<<username<<endl;
		pthread_exit(NULL);
	}
    
    BIO_free(mbio);
	return;
}

string SecureChatServer::receiveAuthentication(int process_socket, unsigned int &status){
    char* authentication_buf = (char*)malloc(AUTHENTICATION_MAX_SIZE);
    if (!authentication_buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }

    //IMPORTANTE: socket non può essere utilizzato da altri thread perchè l'istanza della classe User non è stata creata
    unsigned int authentication_len = recv(process_socket, (void*)authentication_buf, AUTHENTICATION_MAX_SIZE, 0);
    if (authentication_len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the authentication message"<<endl;
        exit(1);
    }
    cout<<"Thread "<<gettid()<<": Authentication message received"<<endl;

    checkLogout(process_socket, authentication_buf, authentication_len, 0, "");
    status = authentication_buf[0];
    if (status != 0 && status != 1){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'authentication type'."<<endl;
        exit(1);
    }
    unsigned int username_len = authentication_buf[1];
    if (username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Username length is over the upper bound."<<endl;
    }
    string username;
    if (2 + (unsigned long)authentication_buf < 2){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    username.append(authentication_buf+2, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    if (username_len + 2 < username_len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int clear_message_len = 2 + username_len;
    if (authentication_buf + clear_message_len < authentication_buf){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }

    memcpy(signature, authentication_buf+clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        exit(1);
    }
    memcpy(clear_message, authentication_buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error while receiving the authentication"<<endl;
        exit(1);
    }
    cout<<"Thread "<<gettid()<<": Authentication of authentication message is ok"<<endl;

    return username;
}

void SecureChatServer::changeUserStatus(string username, unsigned int status, int user_socket){
    cout<<"changeUserStatus(): "<<username.length()<<endl;
    pthread_mutex_lock(&(*users).at(username).user_mutex);
    (*users).at(username).status = status;
    (*users).at(username).socket = user_socket;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);
}

void SecureChatServer::printUserList(){
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        it->second.printUser();
    }
}

vector<User> SecureChatServer::getOnlineUsers(){
    vector<User> v;
    for (map<string,User>::iterator it=(*users).begin(); it!=(*users).end(); ++it){
        if (it->second.status == 1){
            v.push_back(it->second);
        }
    }
    return v;
}

void SecureChatServer::sendAvailableUsers(int data_socket, string username){
    char buf[AVAILABLE_USER_MAX_SIZE];
    buf[0] = 2;
    vector<User> available = getOnlineUsers();
    if (available.size() > MAX_AVAILABLE_USER_MESSAGE){
        buf[1] = MAX_AVAILABLE_USER_MESSAGE;
    }
    else{
        buf[1] = available.size();
    }
    unsigned int len = 2;
    // |2|2|5|alice|3|bob| -> 14
    for (unsigned int i = 0; i < available.size(); i++){
        if (available[i].username.compare(username) != 0){ //TODO: Ricordiamoci di riattivare questo controllo
            if (len >= AVAILABLE_USER_MAX_SIZE){
                cerr<<"Access our-of-bound"<<endl;
                pthread_exit(NULL);
            }
            buf[len] = available[i].username.length();
            if (len + 1 == 0){
                cerr<<"Wrap around"<<endl;
                pthread_exit(NULL);
            }
            len++;
            if (len + (unsigned long)buf < len){
                cerr<<"Wrap around"<<endl;
                pthread_exit(NULL);
            }
            if (len + available[i].username.length() < len){
                cerr<<"Wrap around"<<endl;
                pthread_exit(NULL);
            }
            if (len + available[i].username.length() >= AVAILABLE_USER_MAX_SIZE){
                cerr<<"Access out-of-bound"<<endl;
                pthread_exit(NULL);
            }
            memcpy(buf+len, available[i].username.c_str(), available[i].username.length()); //TODO: controllare se c'e' il fine stringa
            len += available[i].username.length();
        }
    }

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, buf, len, &signature, &signature_len);

    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    if (len + signature_len >= AVAILABLE_USER_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        pthread_exit(NULL);
    }
    if (len + (unsigned long)buf < len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int msg_len = len + signature_len;
    memcpy(buf+len, signature, signature_len);
    
    if (send(data_socket, buf, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<"Error in the sendto of the available user list"<<endl;
		pthread_exit(NULL);
	}

}

string SecureChatServer::receiveRTT(int data_socket, string username){
    char* buf = (char*)malloc(RTT_MAX_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }


    pthread_mutex_lock(&(*users).at(username).user_mutex);
    unsigned int len = recv(data_socket, (void*)buf, RTT_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the RTT message"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": RTT message received"<<endl;
    pthread_mutex_unlock(&(*users).at(username).user_mutex);

    checkLogout(data_socket, buf, len, 1, username);

    unsigned int message_type = buf[0];
    if (message_type != 3){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'RTT type'."<<endl;
        pthread_exit(NULL);
    }
    unsigned int receiver_username_len = buf[1];
    if (receiver_username_len > USERNAME_MAX_SIZE){
        cerr<<"Thread "<<gettid()<<": Receiver Username length is over the upper bound."<<endl;
    }
    string receiver_username;
    if (receiver_username_len + 2 < receiver_username_len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int clear_message_len = receiver_username_len + 2;
    if (clear_message_len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        pthread_exit(NULL);
    }
    receiver_username.append(buf+2, receiver_username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }
    if (clear_message_len + (unsigned long)buf < clear_message_len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Authentication of RTT is ok"<<endl;

    return receiver_username;
}

void SecureChatServer::forwardRTT(string receiver_username, string sender_username){
    //TODO gestire la RTT inviandola al receiver
    int data_socket = (*users).find(receiver_username)->second.socket;
    // 3 | sender_username_len | sender_username | digest
    char msg[RTT_MAX_SIZE];
    msg[0] = 3; //Type = 3, request to talk message
    char sender_username_len = sender_username.length(); //receiver_username length on one byte
    msg[1] = sender_username_len;
    if (sender_username_len + 2 < sender_username_len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = sender_username_len + 2;
    if (len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    if (2 + (unsigned long)msg < 2){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    memcpy((msg+2), sender_username.c_str(), sender_username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int msg_len = len + signature_len;
    if (msg_len >= RTT_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(msg + len, signature, signature_len);
    
    if (send(data_socket, msg, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the RTT"<<endl;
		pthread_exit(NULL);
	}
}

string SecureChatServer::receiveResponse(int data_socket, string receiver_username, unsigned int &response){
    // 4 | response | 5 | mbala | digest
    char* buf = (char*)malloc(RESPONSE_MAX_SIZE);
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }

    pthread_mutex_lock(&(*users).at(receiver_username).user_mutex);
    unsigned int len = recv(data_socket, (void*)buf, RESPONSE_MAX_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving the Response to RTT message"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Response to RTT message received"<<endl;
    pthread_mutex_unlock(&(*users).at(receiver_username).user_mutex);

    checkLogout(data_socket, buf, len, 1, receiver_username);
    unsigned int message_type = buf[0];
    if (message_type != 4){
        cerr<<"Thread "<<gettid()<<": Message type is not corresponding to 'Response to RTT type'."<<endl;
        pthread_exit(NULL);
    }

    response = buf[1];

    unsigned int username_len = buf[2];

    if (3 + (unsigned long)buf < 3){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    if (3 + username_len < 3){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    unsigned int clear_message_len = 3 + username_len;
    if (clear_message_len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        pthread_exit(NULL);
    }
    string sender_username;
    sender_username.append(buf+3, username_len);

    unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }
    if (clear_message_len + (unsigned long)buf < clear_message_len){
        cerr<<"Wrap around"<<endl;
        pthread_exit(NULL);
    }
    memcpy(signature, buf + clear_message_len, SIGNATURE_SIZE);

    char* clear_message = (char*)malloc(clear_message_len);
    if (!clear_message){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }
    memcpy(clear_message, buf, clear_message_len);
    EVP_PKEY* pubkey = getUserKey(receiver_username);

    if(Utility::verifyMessage(pubkey, clear_message, clear_message_len, signature, SIGNATURE_SIZE) != 1) { 
        cerr<<"Thread "<<gettid()<<": Authentication error for Response to RTT"<<endl;
        pthread_exit(NULL);
    }
    cout<<"Thread "<<gettid()<<": Response to RTT received equal to "<<response<<endl;

    if ((*users).at(receiver_username).responses.count(sender_username)!=0)
        (*users).at(receiver_username).responses.at(sender_username) = response;
    else
        (*users).at(receiver_username).responses.insert(pair<string, unsigned int>(sender_username, response));

    return sender_username;
}

void SecureChatServer::forwardResponse(string sender_username, unsigned int response){
    int data_socket = (*users).at(sender_username).socket;
    // 4 | response | 5 | mbala | digest
    char msg[RESPONSE_MAX_SIZE];
    msg[0] = 4; //Type = 4, response to request to talk message
    msg[1] = response;

    unsigned int username_len = sender_username.length();
    msg[2] = username_len;

    if (3 + username_len < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int len = 3 + username_len;
    if (len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    if (3 + (unsigned long)msg < 3){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }

    memcpy(msg+3, sender_username.c_str(), username_len);

    unsigned char* signature;
    unsigned int signature_len;
    Utility::signMessage(server_prvkey, msg, len, &signature, &signature_len);

    if (len + (unsigned long)msg < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    if (len + signature_len < len){
        cerr<<"Wrap around"<<endl;
        exit(1);
    }
    unsigned int msg_len = len + signature_len;
    if (msg_len > RESPONSE_MAX_SIZE){
        cerr<<"Access out-of-bound"<<endl;
        exit(1);
    }
    memcpy(msg + len, signature, signature_len);
    
    if (send(data_socket, msg, msg_len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }
}

void SecureChatServer::checkLogout(int data_socket, char* msg, unsigned int buffer_len, unsigned int auth_required, string username){
    if(msg[0] != 8)
        return;

    if(msg[1] == 0){
        if(auth_required == 1) //it is not possible to accept logout
            return;
        close(data_socket);
        pthread_exit(NULL);
    }
    else{
        unsigned char* signature = (unsigned char*)malloc(SIGNATURE_SIZE);
        if (!signature){
            cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
            pthread_exit(NULL);
        }
        if (2 + (unsigned long)msg < 2){
            cerr<<"Wrap around"<<endl;
            pthread_exit(NULL);
        }
        memcpy(signature, msg+2, SIGNATURE_SIZE);

        char* clear_message = (char*)malloc(2);
        if (!clear_message){
            cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
            pthread_exit(NULL);
        }
        memcpy(clear_message, msg, 2);

        EVP_PKEY* pubkey = getUserKey(username);

        if(Utility::verifyMessage(pubkey, clear_message, 2, signature, SIGNATURE_SIZE) != 1) { 
            cerr<<"Thread "<<gettid()<<": logout not accepted"<<endl;
            return;
        }

        pthread_mutex_lock(&(*users).at(username).user_mutex);
        close(data_socket);
        pthread_mutex_unlock(&(*users).at(username).user_mutex);
        pthread_exit(NULL);
    }
}

char* SecureChatServer::receive(int data_socket, string username, unsigned int &len, char* buf){
    if (!buf){
        cerr<<"There is not more space in memory to allocate a new buffer"<<endl;
        pthread_exit(NULL);
    }

    //pthread_mutex_lock(&(*users).at(username).user_mutex);
    len = recv(data_socket, (void*)buf, GENERAL_MSG_SIZE, 0);
    if (len < 0){
        cerr<<"Thread "<<gettid()<<": Error in receiving a message"<<endl;
        pthread_exit(NULL);
    }
    //pthread_mutex_unlock(&(*users).at(username).user_mutex);

    cout<<"Marcelloni: "<<endl;
    for (int i = 0; i < 5; i++){
        printf("%02hhx", buf[i]);
    }
    cout<<endl;

    return buf;
}

void SecureChatServer::forward(string username, char* msg, unsigned int len){
    cout<<"Ducange: "<<endl;
    for (int i = 0; i < 5; i++){
        printf("%02hhx", msg[i]);
    }
    cout<<endl;
    int data_socket = (*users).at(username).socket;
    if (send(data_socket, msg, len, 0) < 0){
		cerr<<"Thread "<<gettid()<<": Error in the forward of the Response to RTT"<<endl;
		pthread_exit(NULL);
    }
}