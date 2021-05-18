#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <string>

#ifndef CYBERSECURITYPROJECT_UTILITY_H
#define CYBERSECURITYPROJECT_UTILITY_H

using namespace std;

class Utility {
    private:

    public:
        static EVP_PKEY* readPrvKey(string path, void* password);

        static EVP_PKEY* readPubKey(string path, void* password);

        static X509* readCertificate(string path);

        static X509_CRL* readCRL(string path);

        static int verifyMessage(EVP_PKEY* pubkey, unsigned char* clear_message, int clear_message_len, unsigned char* signature, int signature_len);

        static void signMessage(EVP_PKEY* privkey, unsigned char* msg, int len, unsigned char** signature, unsigned int* signature_len);
};

#endif