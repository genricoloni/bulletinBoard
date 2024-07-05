#include "RSASignature.hpp"

RSASignature::RSASignature(const std::string& privateKeyPath, const std::string& publicKeyPath) {
    mPublicKey = nullptr;
    mPrivateKey = nullptr;

    if(!privateKeyPath.empty()) {
        BIO* bio = nullptr;
        bio = BIO_new_file(privateKeyPath.c_str(), "r");
        if (!bio) 
            throw std::runtime_error("Failed to open private key file");
        
        mPrivateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);

    if(!mPrivateKey){
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to read private key");      
        }
    }
    if (!publicKeyPath.empty()) {
        BIO* bio = nullptr;
        bio = BIO_new_file(publicKeyPath.c_str(), "r");
        if (!bio) 
            throw std::runtime_error("Failed to open public key file");
        
        mPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if(!mPublicKey){
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to read public key");      
        }
    }
}


std::vector<unsigned char> RSASignature::sign(const std::vector<unsigned char>& message) {
    if(!mPrivateKey) {
        throw std::runtime_error("Private key not loaded");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* privateKey = mPrivateKey;

    if(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privateKey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Error initializing signature");
    }

    if(EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Error updating signature");
    }

    size_t signatureLength;

    if (EVP_DigestSignFinal(ctx, NULL, &signatureLength) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Error finalizing signature");
    }

    std::vector<unsigned char> signature(signatureLength);
    if(EVP_DigestSignFinal(ctx, signature.data(), &signatureLength) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Error finalizing signature");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    return signature;
}

bool RSASignature::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) {
    if(!mPublicKey) {
        throw std::runtime_error("Public key not loaded");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* publicKey = mPublicKey;

    if(EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publicKey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        throw std::runtime_error("Error initializing verification");
    }

    if(EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        throw std::runtime_error("Error updating verification");
    }

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    return result == 1;
}