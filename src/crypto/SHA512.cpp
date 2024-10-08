#include "SHA512.hpp"
#include <cstdio>

void SHA512::generateHash(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<uint8_t>& digest, unsigned int& digestLength) {
    
    digest.resize(EVP_MD_size(EVP_sha512()));

    #ifdef DEBUG
    printf("DEBUG>> Digest size: %zu\n", digest.size());
    #endif

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        throw std::runtime_error("Error creating context");
    }

    #ifdef DEBUG
    printf("DEBUG>> Context created\n");
    #endif

    if(EVP_DigestInit(mdctx, EVP_sha512()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error initializing digest");
    }

    #ifdef DEBUG
    printf("DEBUG>> Digest initialized\n");
    //print the address of the context
    printf("DEBUG>> Context address: %p\n", mdctx);
    //print the address of the buffer
    printf("DEBUG>> Buffer address: %p\n", inputBuffer);
    #endif

    try {
        if(EVP_DigestUpdate(mdctx, inputBuffer, inputBufferLength) != 1) {
            #ifdef DEBUG
            printf("DEBUG>> Error updating digest\n");
            #endif
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Error updating digest");
        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        #ifdef DEBUG
        printf("DEBUG>> Error: %s\n", e.what());
        #endif
        throw e;
    }

    #ifdef DEBUG
    printf("DEBUG>> Digest updated\n");
    #endif

    if(EVP_DigestFinal(mdctx, digest.data(), &digestLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error finalizing digest");
    }

    #ifdef DEBUG
    printf("DEBUG>> Digest finalized\n");
    #endif

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