#include <string>
#include "Utility.h"

const unsigned int USERNAME_MAX_SIZE = 16;
const unsigned int MAX_ADDRESS_SIZE = 16;
const unsigned int MAX_USERS_TO_SEND = 64;

const unsigned int BUFFER_SIZE = 1024;
const int CERTIFICATE_MAX_SIZE = 2048;
const int DIGEST_SIZE = EVP_MD_size(EVP_sha256());
const int SIGNATURE_SIZE = 256;
const int AUTHENTICATION_MAX_SIZE = USERNAME_MAX_SIZE + 3 + SIGNATURE_SIZE;
const int MAX_AVAILABLE_USER_MESSAGE = 10;
const int AVAILABLE_USER_MAX_SIZE = 2 + MAX_AVAILABLE_USER_MESSAGE*(USERNAME_MAX_SIZE+2) + SIGNATURE_SIZE;
const int RTT_MAX_SIZE = 3 + USERNAME_MAX_SIZE + SIGNATURE_SIZE;
