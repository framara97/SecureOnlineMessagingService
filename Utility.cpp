#include "Utility.h"
#include <iostream>

EVP_PKEY* Utility::readPrvKey(string path, void* password) {

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

    //Open the public key file in read mode
    printf("%s\n", path.c_str());
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

int Utility::verifyMessage(EVP_PKEY* pubkey, char* clear_message, int clear_message_len, unsigned char* signature, int signature_len){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, clear_message, clear_message_len);
    int ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}

void Utility::signMessage(EVP_PKEY* privkey, char* msg, int len, unsigned char** signature, unsigned int* signature_len){
    *signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, (unsigned char*)msg, len);
    EVP_SignFinal(ctx, *signature, &*signature_len, privkey);
    cout<<*signature_len<<endl;
    EVP_MD_CTX_free(ctx);
}

bool Utility::isNumeric(string str){
   for (int i = 0; i < str.length(); i++)
      if (isdigit(str[i]) == false)
         return false;
      return true;
}