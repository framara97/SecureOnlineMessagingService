#include <string>

//Fields
const unsigned int USERNAME_MAX_SIZE = 16;
const unsigned int MAX_ADDRESS_SIZE = 16;
const unsigned int MAX_USERS_TO_SEND = 64;
const unsigned int CERTIFICATE_MAX_SIZE = 2048;
const unsigned int R_SIZE = 16;
const unsigned int GCM_IV_SIZE = 12;
const unsigned int TAG_SIZE = 16;
const unsigned int K_SIZE = 16;
const unsigned int DIGEST_SIZE = EVP_MD_size(EVP_sha256());
const unsigned int SIGNATURE_SIZE = 256;
const unsigned int BLOCK_SIZE = 16;
const unsigned int ENCRYPTED_KEY_SIZE = 384;
const unsigned int NONCE_SIZE = 16;
const unsigned int MAX_AVAILABLE_USER_MESSAGE = 255;
const unsigned int PUBKEY_SIZE = 1024;
const unsigned int ENC_FIELDS = TAG_SIZE + BLOCK_SIZE + GCM_IV_SIZE;

//Messages
const unsigned int AVAILABLE_USER_MAX_SIZE = 2 + MAX_AVAILABLE_USER_MESSAGE*(USERNAME_MAX_SIZE+2);
const unsigned int RTT_MAX_SIZE = 3 + USERNAME_MAX_SIZE + SIGNATURE_SIZE;
const unsigned int RESPONSE_MAX_SIZE = SIGNATURE_SIZE + USERNAME_MAX_SIZE + 3;
const unsigned int LOGOUT_MAX_SIZE = 2 + NONCE_SIZE + SIGNATURE_SIZE;
const unsigned int PUBKEY_MSG_SIZE = 1 + PUBKEY_SIZE + SIGNATURE_SIZE; //TOOD: ricontrollare
const unsigned int M1_SIZE = 1 + R_SIZE + SIGNATURE_SIZE;
const unsigned int INPUT_SIZE = 10000;
const unsigned int GENERAL_MSG_SIZE = 1 + INPUT_SIZE + sizeof(unsigned int) + BLOCK_SIZE + SIGNATURE_SIZE; 
const unsigned int M2_SIZE = 1 + R_SIZE + 1024 + SIGNATURE_SIZE;
const unsigned int M3_SIZE = 3*BLOCK_SIZE+ENCRYPTED_KEY_SIZE+SIGNATURE_SIZE+1000; //one block for K (16), one block for IV (16), the encrypted key and the signature
const unsigned int LOGOUT_NONCE_MSG_SIZE = 3*BLOCK_SIZE+ENCRYPTED_KEY_SIZE+SIGNATURE_SIZE+1000;
const unsigned int S1_SIZE = CERTIFICATE_MAX_SIZE + R_SIZE;
const unsigned int S2_SIZE = 1 + 2*R_SIZE + sizeof(long) + PUBKEY_SIZE + 1 + USERNAME_MAX_SIZE + SIGNATURE_SIZE;
const unsigned int S3_SIZE = 1 + R_SIZE + 3*BLOCK_SIZE + ENCRYPTED_KEY_SIZE + SIGNATURE_SIZE;