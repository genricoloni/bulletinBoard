#include <ctime>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>

#define ENCRYPT         0
#define DECRYPT         1
#define AES_KEY_SIZE    256

class AESCBC {
public:
    AESCBC(uint8_t type, const std::vector<uint8_t>&key);
    AESCBC(uint8_t type, const std::vector<uint8_t>&key, const bool iv);
    AESCBC(const AESCBC&) = delete;
    ~AESCBC();
    void run(const std::vector<uint8_t>&input, std::vector<uint8_t>&output, std::vector<uint8_t>&iv);
    static int getIVLength() {return EVP_CIPHER_iv_length(EVP_aes_256_cbc());}

private:
    uint8_t type;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    uint32_t processedBytes;
    
    bool ivType;
    
    EVP_CIPHER_CTX *ctx;
    
    void initializeEncrypt();
    void updateEncrypt();
    void finalizeEncrypt();
    
    void initializeDecrypt();
    void updateDecrypt();
    void finalizeDecrypt();
};
