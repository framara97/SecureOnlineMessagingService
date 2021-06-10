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
        cerr<<"Error in reading the certificate from the file"<<endl;
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
        cerr<<"Error in reading the CRL from the file"<<endl;
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
    *signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
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
    char* argv1[5] = {strdup("genrsa"), strdup("-out"), strdup(""), strdup("3072"), NULL};
    EVP_PKEY* tprivk;
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    argv1[2] = (char*)malloc(tprivk_path.length()+1);
    if(!argv1[2]){ cerr<<"Malloc didn't work"<<endl; exit(1); }
    strncpy(argv1[2], tprivk_path.c_str(), tprivk_path.length());
    argv1[2][tprivk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){ execv("/bin/openssl", argv1); exit(0); }
    if (pid < 0){ cerr<<"Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
    FILE* file = fopen(tprivk_path.c_str(), "r");
    if(!file){ cerr<<"Error while reading the fileX"<<endl; exit(1); }
    tprivk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!tprivk) { cerr<<"Error while reading the private key"<<endl; exit(1); }
    fclose(file);
    return tprivk;
}

EVP_PKEY* Utility::generateTpubK(string username){
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    pid_t pid;
    string tpubk_path = "./client/" + username + "/tpubk.pem";
    char* argv2[7] = {strdup("rsa"), strdup("-pubout"), strdup("-in"), strdup(""), strdup("-out"), strdup(""), NULL};
    argv2[3] = (char*)malloc(tprivk_path.length()+1);
    if (!argv2[3]){ cerr<<"Malloc didn't work"<<endl; exit(1); }
    strncpy(argv2[3], tprivk_path.c_str(), tprivk_path.length());
    argv2[3][tprivk_path.length()] = '\0';
    argv2[5] = (char*)malloc(tpubk_path.length()+1);
    if (!argv2[5]){ cerr<<"Malloc didn't work"<<endl; exit(1); }
    strncpy(argv2[5], tpubk_path.c_str(), tpubk_path.length());
    argv2[5][tpubk_path.length()] = '\0';
    pid = fork();
    if (pid == 0){ execv("/bin/openssl", argv2); exit(0); }
    if (pid < 0){ cerr<<"Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
    EVP_PKEY* tpubk;
    FILE* file = fopen(tpubk_path.c_str(), "r");
    if(!file){ cerr<<"Error while reading the file"<<endl; exit(1); }
    tpubk = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!tpubk){ cerr<<"Error while reading the public key"<<endl; exit(1); }
    fclose(file);
    return tpubk;
}

void Utility::removeTprivK(string username){
    string tprivk_path = "./client/" + username + "/tprivk.pem";
    char* argv4[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv4[1] = (char*)malloc(tprivk_path.length());
    if (!argv4[1]){ cerr<<"Malloc didn't work"<<endl; exit(1); }
    strncpy(argv4[1], tprivk_path.c_str(), tprivk_path.length());
    argv4[1][tprivk_path.length()] = '\0';
    pid_t pid = fork();
    if (pid == 0){ execv("/bin/rm", argv4); exit(0); }
    if (pid < 0){ cerr<<"Error while creating a new process"<<endl; exit(1); }
    waitpid(pid, NULL, 0);
}

void Utility::removeTpubK(string username){
    string tpubk_path = "./client/" + username + "/tpubk.pem";
    char* argv3[3] = {strdup("/bin/rm"), strdup(""), NULL};
    argv3[1] = (char*)malloc(tpubk_path.length()+1);
    if (!argv3[1]){ cerr<<"Malloc didn't work"<<endl; exit(1); }
    strncpy(argv3[1], tpubk_path.c_str(), tpubk_path.length());
    argv3[1][tpubk_path.length()] = '\0';
    pid_t pid = fork();
    if (pid == 0){ execv("/bin/rm", argv3); exit(0); }
    if (pid < 0){ cerr<<"Error while creating a new process"<<endl; exit(1); }
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
    if(ok==false) { cout<<"Nonce R not correctly exchanged"<<endl; }
    else { cout<<"Nonce R correctly exchanged"<<endl; }
    return ok;
}

bool Utility::encryptMessage(int plaintext_len, EVP_PKEY* pubkey, unsigned char* plaintext, unsigned char* &ciphertext, unsigned char* &encrypted_key, unsigned char* &iv, int& encrypted_key_len, int& outlen, unsigned int& cipherlen){
    encrypted_key = (unsigned char*)malloc(EVP_PKEY_size(pubkey));
    ciphertext = (unsigned char*)malloc(plaintext_len + 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    cipherlen = 0;
    iv = (unsigned char*) malloc(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    int ret = EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
    if(ret == 0) { return false; }
    ret = EVP_SealUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, plaintext_len);
    if(ret == 0) { return false; }
    if (cipherlen + outlen < cipherlen){ cerr<<"Wrap around"<<endl; exit(1); }
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
    if (plaintext_len + outlen < plaintext_len){ cerr<<"Wrap around"<<endl; exit(1); }
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

bool Utility::encryptSessionMessage(int plaintext_len, unsigned char* key, unsigned char* plaintext, unsigned char* &ciphertext, int& outlen, unsigned int& cipherlen){
    ciphertext = (unsigned char*)malloc(plaintext_len + BLOCK_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    cipherlen = 0;
    int ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, NULL);
    if(ret == 0) { return false; }
    ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, plaintext_len);
    if(ret == 0) { return false; }
    if (cipherlen + outlen < cipherlen){ cerr<<"Wrap around"<<endl; exit(1); }
    cipherlen += outlen;
    ret = EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
    if(ret == 0) { return false; }
    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool Utility::decryptSessionMessage(unsigned char* &plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char* key, unsigned int& plaintext_len){
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    plaintext_len = 0;
    unsigned int ret = EVP_DecryptInit(ctx, cipher, key, NULL);
    if(ret == 0) { return false; }
    EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &outlen, ciphertext, ciphertext_len);
    if (plaintext_len + outlen < plaintext_len){ cerr<<"Wrap around"<<endl; exit(1); }
    plaintext_len += outlen;
    ret = EVP_DecryptFinal(ctx, plaintext + plaintext_len, &outlen);
    if(ret == 0) { return false; }
    plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}