#include <string>
#include "Utility.h"

const unsigned int USERNAME_MAXSIZE = 16;
const unsigned int MAX_USERS_TO_SEND = 64;

const unsigned int BUFFER_SIZE = 1024;
const int CERTIFICATE_MAX_SIZE = 2048;
const int DIGEST_SIZE = EVP_MD_size(EVP_sha256());
const int AUTHENTICATION_MAX_SIZE = /*USERNAME_MAXSIZE + 2 + DIGEST_SIZE*/ 4096;