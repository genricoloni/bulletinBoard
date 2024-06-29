#include "HMAC.hpp"

HMAC::HMAC(const unsigned char* key) {
    mKey = new unsigned char[HMAC_DIGEST_SIZE];
    memcpy(mKey, key, HMAC_DIGEST_SIZE);
}

HMAC::~HMAC() {
    memset(mKey, 0, HMAC_DIGEST_SIZE);
    delete[] mKey;
}

void HMAC::generateHMAC(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<uint8_t>& digest, unsigned int& digestLength) {
    digest.resize(EVP_MD_size(EVP_sha256()));
    HMAC_CTX *ctx = HMAC_CTX_new();

    if(!ctx) {
        throw std::runtime_error("Error creating context");
    }

    if(HMAC_Init_ex(ctx, mKey, HMAC_DIGEST_SIZE, EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("Error initializing HMAC");
    }

    if(HMAC_Update(ctx, inputBuffer, inputBufferLength) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("Error updating HMAC");
    }

    if(HMAC_Final(ctx, digest.data(), &digestLength) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("Error finalizing HMAC");
    }

    HMAC_CTX_free(ctx);
}

bool HMAC::verifyHMAC(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<unsigned char>& digest) {
    std::vector<uint8_t> generatedDigest;
    unsigned int digestLength;

    try{
        HMAC::generateHMAC(inputBuffer, inputBufferLength, generatedDigest, digestLength);
        return CRYPTO_memcmp(digest.data(), generatedDigest.data(), EVP_MD_size(EVP_sha256())) == 0;
    } catch(...) {
        throw;
    }
}