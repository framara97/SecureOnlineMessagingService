#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <string>
#include "constants.h"

#ifndef CYBERSECURITYPROJECT_UTILITY_H
#define CYBERSECURITYPROJECT_UTILITY_H

using namespace std;

class Utility {
    private:

    public:
        static const char* HOME_DIR;

        static EVP_PKEY* readPrvKey(string path, void* password);

        static EVP_PKEY* readPubKey(string path, void* password);

        static X509* readCertificate(string path);

        static X509_CRL* readCRL(string path);

        static int verifyMessage(EVP_PKEY* pubkey, char* clear_message, unsigned int clear_message_len, unsigned char* signature, unsigned int signature_len);

        static void signMessage(EVP_PKEY* privkey, char* msg, unsigned int len, unsigned char** signature, unsigned int* signature_len);

        static bool isNumeric(string str); //check is a string is composed only by digit characters

        static EVP_PKEY* generateTprivK(string username);

        static EVP_PKEY* generateTpubK(string username);

        static void removeTprivK(string username);

        static void removeTpubK(string username);

        static void printPublicKey(EVP_PKEY* key);

        static bool compareR(const unsigned char* R1, const unsigned char* R2);

        static bool encryptMessage(int plaintext_len, EVP_PKEY* pubkey, unsigned char* plaintext, unsigned char* &ciphertext, unsigned char* &encrypted_key, unsigned char* &iv, int& encrypted_key_len, int& outlen, unsigned int& cipherlen);

        static bool decryptMessage(unsigned char* &plaintext, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* iv, unsigned char* encrypted_key, unsigned int encrypted_key_len, EVP_PKEY* prvkey, unsigned int& plaintext_len);

        static void printMessage(string print_message, unsigned char* buf, unsigned int len);

        static void printChatMessage(string print_message, char* buf, unsigned int len);

        static bool encryptSessionMessage(int plaintext_len, unsigned char* key, unsigned char* plaintext, unsigned char* &ciphertext, int& outlen, unsigned int& cipherlen);

        static bool decryptSessionMessage(unsigned char* &plaintext, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char* key, unsigned int& plaintext_len);
};

#endif