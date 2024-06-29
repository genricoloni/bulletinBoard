#include "SHA512.hpp"

void SHA512::generateHash(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<uint8_t>& digest, unsigned int& digestLength) {
    
    digest.resize(EVP_MD_size(EVP_sha512()));

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        throw std::runtime_error("Error creating context");
    }

    if(EVP_DigestInit(mdctx, EVP_sha512()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error initializing digest");
    }

    if(EVP_DigestUpdate(mdctx, inputBuffer, inputBufferLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error updating digest");
    }

    if(EVP_DigestFinal(mdctx, digest.data(), &digestLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error finalizing digest");
    }

    EVP_MD_CTX_free(mdctx);
};

bool SHA512::verifyHash(const unsigned char* inputBuffer, size_t inputBufferLength, const unsigned char* digest) {
    std::vector<uint8_t> generatedDigest;
    unsigned int digestLength;

    try{
        SHA512::generateHash(inputBuffer, inputBufferLength, generatedDigest, digestLength);
        return CRYPTO_memcmp(digest, generatedDigest.data(), EVP_MD_size(EVP_sha256())) == 0;
    } catch(...) {
        throw;
    }

}