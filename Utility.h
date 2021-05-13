#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <string>

using namespace std;

class Utility {
    private:

    public:
        static EVP_PKEY* readPrvKey(string path, void* password);
};