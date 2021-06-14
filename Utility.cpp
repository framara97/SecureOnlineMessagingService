#include "Utility.h"
#include <iostream>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

const char* Utility::HOME_DIR = "/home/";

EVP_PKEY* Utility::readPrvKey(string path, void* password) {
    char* canon_path = realpath(path.c_str(), NULL);
    if(!canon_path) return NULL;
    if(strncmp(canon_path, HOME_DIR, strlen(HOME_DIR)) != 0) { free(canon_path); return NULL; }
    ifstream f(canon_path, ios::in);
    free(canon_path);
    if(!f) { cerr << "Cannot open " << path << endl; return NULL; }

    //Open the private key file in read mode
    FILE* prvkey_file = fopen(path.c_str(), "r");
    if(!prvkey_file){
        cerr << "Error in reading private key file.."<<endl;
        exit(1);
    }

    //Read the private key from the given file into a EVP_PKEY structure
    EVP_PKEY* prvkey;
    prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, password);
    fclose(prvkey_file);
    if(!prvkey){
        cerr << "Error in reading the private key from the file"<<endl;
        exit(1);
    }
    return prvkey;
}

EVP_PKEY* Utility::readPubKey(string path, void* password) {
    char* canon_path = realpath(path.c_str(), NULL);
    if(!canon_path) return NULL;
    if(strncmp(canon_path, HOME_DIR, strlen(HOME_DIR)) != 0) { free(canon_path); return NULL; }
    ifstream f(canon_path, ios::in);
    free(canon_path);
    if(!f) { cerr << "Cannot open " << path << endl; return NULL; }

    //Open the public key file in read mode
    FILE* pubkey_file = fopen(path.c_str(), "r");
    if(!pubkey_file){
        cerr << "Error in reading public key file.."<<endl;
        exit(1);
    }

    //Read the public key from the given file into a EVP_PKEY structure
    EVP_PKEY* pubkey;
    pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, password);
    fclose(pubkey_file);
    if(!pubkey){
        cerr << "Error in reading the public key from the file"<<endl;
        exit(1);
    }
    return pubkey;
}

X509* Utility::readCertificate(string path){
    char* canon_path = realpath(path.c_str(), NULL);
    if(!canon_path) return NULL;
    if(strncmp(canon_path, HOME_DIR, strlen(HOME_DIR)) != 0) { free(canon_path); return NULL; }
    ifstream f(canon_path, ios::in);
    free(canon_path);
    if(!f) { cerr << "Cannot open " << path << endl; return NULL; }

    //Open the certificate file in read mode
    FILE* cert_file = fopen(path.c_str(), "r");
    if (!cert_file){
        cerr << "Error in reading certificate file.."<<endl;
        exit(1);
    }
    
    //Read the certificate from the given file into a X509 structure
    X509* certificate;
    certificate = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!certificate){
        cerr<<"ERR: Error in reading the certificate from the file"<<endl;
        exit(1);
    }
    return certificate;
}

X509_CRL* Utility::readCRL(string path){
    char* canon_path = realpath(path.c_str(), NULL);
    if(!canon_path) return NULL;
    if(strncmp(canon_path, HOME_DIR, strlen(HOME_DIR)) != 0) { free(canon_path); return NULL; }
    ifstream f(canon_path, ios::in);
    free(canon_path);
    if(!f) { cerr << "Cannot open " << path << endl; return NULL; }

    //Open the CRL file in read mode
    FILE* crl_file = fopen(path.c_str(), "r");
    if (!crl_file){
        cerr << "Error in reading CRL file.."<<endl;
        exit(1);
    }
    
    //Read the CRL from the given file into a X509 structure
    X509_CRL* crl;
    crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){
        cerr<<"ERR: Error in reading the CRL from the file"<<endl;
        exit(1);
    }
    return crl;
}

int Utility::verifyMessage(EVP_PKEY* pubkey, char* clear_message, unsigned int clear_message_len, unsigned char* signature, unsigned int signature_len){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, clear_message, clear_message_len);
    int ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}

void Utility::signMessage(EVP_PKEY* privkey, char* msg, unsigned int len, unsigned char** signature, unsigned int* signature_len){
    //*signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    *signature = (unsigned char*)malloc(SIGNATURE_SIZE);
    if (!signature){
        cout<<"Error in the malloc for the signature"<<endl;
        exit(1);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, (unsigned char*)msg, len);
    EVP_SignFinal(ctx, *signature, &*signature_len, privkey);
    EVP_MD_CTX_free(ctx);
}

bool Utility::isNumeric(string str){
   for (unsigned int i = 0; i < str.length(); i++)
      if (isdigit(str[i]) == false)
         return false;
      return true;
}

EVP_PKEY* Utility::generateTprivK(string username){
    pid_t pid;
    char* argv1[7] = {strdup("genrsa"), strdup("-out"), strdup(""), strdup("3072"), NULL};
    EVP_PKEY* tprivk;
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    argv1[2] = (char*)malloc(tprivk_path.length()+1);
    if(!argv1[2]){ cerr<<"ERR: Malloc didn't work"<<endl; exit(1); }
    strncpy(argv1[2], tprivk_path.c_str(), tprivk_path.length());
    argv1[2][tprivk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){ execv("/bin/openssl", argv1); exit(0); }
    if (pid < 0){ cerr<<"ERR: Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
    FILE* file = fopen(tprivk_path.c_str(), "r");
    if(!file){ cerr<<"ERR: Error while reading the fileX"<<endl; exit(1); }
    tprivk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!tprivk) { cerr<<"ERR: Error while reading the private key"<<endl; exit(1); }
    fclose(file);
    return tprivk;
}

EVP_PKEY* Utility::generateTpubK(string username){
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    pid_t pid;
    string tpubk_path = "./client/" + username + "/tpubk.pem";
    char* argv2[9] = {strdup("rsa"), strdup("-pubout"), strdup("-in"), strdup(""), strdup("-out"), strdup(""), NULL};
    argv2[3] = (char*)malloc(tprivk_path.length()+1);
    if (!argv2[3]){ cerr<<"ERR: Malloc didn't work"<<endl; exit(1); }
    strncpy(argv2[3], tprivk_path.c_str(), tprivk_path.length());
    argv2[3][tprivk_path.length()] = '\0';
    argv2[5] = (char*)malloc(tpubk_path.length()+1);
    if (!argv2[5]){ cerr<<"ERR: Malloc didn't work"<<endl; exit(1); }
    strncpy(argv2[5], tpubk_path.c_str(), tpubk_path.length());
    argv2[5][tpubk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){ execv("/bin/openssl", argv2); exit(0); }
    if (pid < 0){ cerr<<"ERR: Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
    EVP_PKEY* tpubk;
    FILE* file = fopen(tpubk_path.c_str(), "r");
    if(!file){ cerr<<"ERR: Error while reading the file"<<endl; exit(1); }
    tpubk = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!tpubk){ cerr<<"ERR: Error while reading the public key"<<endl; exit(1); }
    fclose(file);
    return tpubk;
}

void Utility::removeTprivK(string username){
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    char* argv4[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv4[1] = (char*)malloc(tprivk_path.length());
    if (!argv4[1]){ cerr<<"ERR: Malloc didn't work"<<endl; exit(1); }
    strncpy(argv4[1], tprivk_path.c_str(), tprivk_path.length());
    argv4[1][tprivk_path.length()] = '\0';
    pid_t pid = fork();
    if (pid == 0){ execv("/bin/rm", argv4); exit(0); }
    if (pid < 0){ cerr<<"ERR: Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
}

void Utility::removeTpubK(string username){
    string tpubk_path = "./client/" + username + "/tpubk.pem";
    char* argv3[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv3[1] = (char*)malloc(tpubk_path.length()+1);
    if (!argv3[1]){ cerr<<"ERR: Malloc didn't work"<<endl; exit(1); }
    strncpy(argv3[1], tpubk_path.c_str(), tpubk_path.length());
    argv3[1][tpubk_path.length()] = '\0';
    pid_t pid = fork();
    if (pid == 0){ execv("/bin/rm", argv3); exit(0); }
    if (pid < 0){ cerr<<"ERR: Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
}

/* ---------------------------------------------------------- *\
|* This function works with both pubkey or privkey as input   *|
\* ---------------------------------------------------------- */
void Utility::printPublicKey(EVP_PKEY* key){
    cout<<"Printing key: "<<endl;
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(bp, key, 0, NULL);
    BIO_free(bp);
}

bool Utility::compareR(const unsigned char* R1, const unsigned char* R2){
    bool ok = true;
    for (int i = 0; i < R_SIZE; i++){ 
        if(R1[i] != R2[i]) { ok = false; break; }
    }
    if(ok==false) { cerr<<"ERR: Nonce R not correctly exchanged"<<endl; }
    return ok;
}

bool Utility::encryptMessage(int plaintext_len, EVP_PKEY* pubkey, unsigned char* plaintext, unsigned char* &ciphertext, unsigned char* &encrypted_key, unsigned char* &iv, int& encrypted_key_len, int& outlen, unsigned int& cipherlen){
    encrypted_key = (unsigned char*)malloc(EVP_PKEY_size(pubkey));
    if (!encrypted_key){ return false; }
    ciphertext = (unsigned char*)malloc(plaintext_len + 16);
    if (!ciphertext){ return false;}
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    cipherlen = 0;
    iv = (unsigned char*) malloc(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    if (!iv){ return false;}
    int ret = EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
    if(ret == 0) { return false; }
    ret = EVP_SealUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, plaintext_len);
    if(ret == 0) { return false; }
    if (cipherlen + outlen < cipherlen){ cerr<<"ERR: Wrap around"<<endl; return false; }
    cipherlen += outlen;
    ret = EVP_SealFinal(ctx, ciphertext + cipherlen, &outlen);
    if(ret == 0) { return false; }
    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool Utility::decryptMessage(unsigned char* &plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char* iv, unsigned char* encrypted_key, unsigned int encrypted_key_len, EVP_PKEY* prvkey, unsigned int& plaintext_len){
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    plaintext_len = 0;
    unsigned int ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvkey);
    if(ret == 0) { return false; }
    EVP_OpenUpdate(ctx, plaintext + plaintext_len, &outlen, ciphertext, ciphertext_len);
    if (plaintext_len + outlen < plaintext_len){ cerr<<"ERR: Wrap around"<<endl; exit(1); }
    plaintext_len += outlen;
    ret = EVP_OpenFinal(ctx, plaintext + plaintext_len, &outlen);
    if(ret == 0) { return false; }
    plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void Utility::printMessage(string print_message, unsigned char* buf, unsigned int len){
    cout<<print_message<<endl;
    for (unsigned int i=0; i < len; i++){
        printf("%02hhx", buf[i]);
    }
    cout<<endl<<"Printed message length: "<<len<<endl;
}

void Utility::printChatMessage(string print_message, char* buf, unsigned int len){
    buf[len] = '\0';
    cout<<print_message<<": "<<buf<<endl;
}

bool Utility::encryptSessionMessage(int plaintext_len, 
                                    unsigned char* key, unsigned char* plaintext, 
                                    unsigned char* &ciphertext, int& outlen, 
                                    unsigned int& ciphertext_len, __uint128_t counter,
                                    unsigned char* &tag, unsigned char* &buf,
                                    unsigned int buf_len, unsigned int server_or_user,
                                    unsigned int &enc_buf_len){

    EVP_CIPHER_CTX *ctx;
    int len=0;
    ciphertext_len=0;
    unsigned char* iv = (unsigned char*)malloc(GCM_IV_SIZE);
    ciphertext = (unsigned char*)malloc(plaintext_len+BLOCK_SIZE);
    tag = (unsigned char*)malloc(TAG_SIZE);
    memcpy(iv, &counter, GCM_IV_SIZE);
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return false;
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return false;
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, iv, GCM_IV_SIZE))
        return false;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return false;
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return false;
    ciphertext_len += len;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return false;
    EVP_CIPHER_CTX_free(ctx);

    enc_buf_len = ciphertext_len + GCM_IV_SIZE + TAG_SIZE;
    if (server_or_user == 0){ //server
        Utility::secure_thread_memcpy(buf, 0, buf_len, iv, 0, GCM_IV_SIZE, GCM_IV_SIZE);
        Utility::secure_thread_memcpy(buf, GCM_IV_SIZE, buf_len, ciphertext, 0, plaintext_len + BLOCK_SIZE, ciphertext_len);
        unsigned int tag_index = ciphertext_len + GCM_IV_SIZE;
        Utility::secure_thread_memcpy(buf, tag_index, buf_len, tag, 0, TAG_SIZE, TAG_SIZE);
        return true;
    }
    if (server_or_user == 1){ //user
        Utility::secure_memcpy(buf, 0, buf_len, iv, 0, GCM_IV_SIZE, GCM_IV_SIZE);
        Utility::secure_memcpy(buf, GCM_IV_SIZE, buf_len, ciphertext, 0, plaintext_len + BLOCK_SIZE, ciphertext_len);
        unsigned int tag_index = ciphertext_len + GCM_IV_SIZE;
        Utility::secure_memcpy(buf, tag_index, buf_len, tag, 0, TAG_SIZE, TAG_SIZE);
        return true;
    }
    return false;
}

bool Utility::decryptSessionMessage(unsigned char* &plaintext, unsigned char *msg, unsigned int msg_len, unsigned char* key, unsigned int& plaintext_len, int server_or_user){
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    unsigned char* iv = (unsigned char*)malloc(GCM_IV_SIZE);
    if (!iv){ return false;}
    unsigned int not_ciphertext_len = GCM_IV_SIZE+TAG_SIZE;
    if (msg_len < not_ciphertext_len){ return false; }
    unsigned int ciphertext_len = msg_len - not_ciphertext_len;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    if (!ciphertext){ return false;}
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE);
    if (!tag) {return false;}
    if (ciphertext_len + GCM_IV_SIZE < ciphertext_len){return false;}
    unsigned int tag_index = ciphertext_len + GCM_IV_SIZE;
    if (server_or_user == 0){ //server
        Utility::secure_thread_memcpy(iv, 0, GCM_IV_SIZE, msg, 0, msg_len, GCM_IV_SIZE);
        Utility::secure_thread_memcpy(ciphertext, 0, ciphertext_len, msg, GCM_IV_SIZE, msg_len, ciphertext_len);
        Utility::secure_thread_memcpy(tag, 0, TAG_SIZE, msg, tag_index, msg_len, TAG_SIZE);
    }
    if (server_or_user == 1){ //user
        Utility::secure_memcpy(iv, 0, GCM_IV_SIZE, msg, 0, msg_len, GCM_IV_SIZE);
        Utility::secure_memcpy(ciphertext, 0, ciphertext_len, msg, GCM_IV_SIZE, msg_len, ciphertext_len);
        Utility::secure_memcpy(tag, 0, TAG_SIZE, msg, tag_index, msg_len, TAG_SIZE);
    }
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return false;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return false;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, iv, GCM_IV_SIZE))
        return false;
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return false;
    plaintext_len = len;
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return false;
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_cleanup(ctx);
    return true;
}

void Utility::secure_memcpy(unsigned char* buf, unsigned int buf_index, unsigned int buf_len, unsigned char* source, unsigned int source_index, unsigned int source_len, unsigned int cpy_size){
    if (buf_index + (unsigned long)buf < buf_index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    if (buf_index + cpy_size < buf_index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    if (buf_index + cpy_size > buf_len){ cerr<<"ERR: Access-out-bound."<<endl; exit(1); }
    if (source_index + cpy_size < source_index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }
    if (source_index + cpy_size > source_len){ cerr<<"ERR: Access-out-bound."<<endl; exit(1); }
    if (source_index + (unsigned long)source < source_index){ cerr<<"ERR: Wrap around."<<endl; exit(1); }

    memcpy(buf+buf_index, source+source_index, cpy_size);
}

void Utility::secure_thread_memcpy(unsigned char* buf, unsigned int buf_index, unsigned int buf_len, unsigned char* source, unsigned int source_index, unsigned int source_len, unsigned int cpy_size){
    if (buf_index + (unsigned long)buf < buf_index){ cerr<<"ERR: Wrap around."<<endl; pthread_exit(NULL); }
    if (buf_index + cpy_size < buf_index){ cerr<<"ERR: Wrap around."<<endl; pthread_exit(NULL); }
    if (buf_index + cpy_size > buf_len){ cerr<<"ERR: Access-out-bound."<<endl; pthread_exit(NULL); }
    if (source_index + cpy_size < source_index){ cerr<<"ERR: Wrap around."<<endl; pthread_exit(NULL); }
    if (source_index + cpy_size > source_len){ cerr<<"ERR: Access-out-bound."<<endl; pthread_exit(NULL); }
    if (source_index + (unsigned long)source < source_index){ cerr<<"ERR: Wrap around."<<endl; pthread_exit(NULL); }

    memcpy(buf+buf_index, source+source_index, cpy_size);
}

bool Utility::compareTag(const unsigned char* tag1, const unsigned char* tag2){
    bool ok = true;
    for (int i = 0; i < TAG_SIZE; i++){ 
        if(tag1[i] != tag2[i]) { ok = false; break; }
    }
    if(ok==false) { cerr<<"ERR: Tag not correctly exchanged"<<endl; }
    return ok;
}