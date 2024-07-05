#include "AESCBC.hpp"

AESCBC::AESCBC(uint8_t type, const std::vector<uint8_t>& key) : type(type), ivType(false), processedBytes(0) {
    
    if(type != ENCRYPT && type != DECRYPT) 
        throw std::runtime_error("Invalid type");
    
    this->key.resize(key.size());
    std::copy(key.begin(), key.end(), this->key.begin());
}

AESCBC::AESCBC(uint8_t type, const std::vector<uint8_t>& key, const bool iv) : type(type), ivType(iv), processedBytes(0) {
    
    if(type != ENCRYPT && type != DECRYPT) 
        throw std::runtime_error("Invalid type");
    
    this->key.resize(key.size());
    std::copy(key.begin(), key.end(), this->key.begin());
}

AESCBC::~AESCBC() {
    EVP_CIPHER_CTX_free(ctx);

    std::memset(this->iv.data(), 0, this->iv.size());
    this->iv.clear();

    std::memset(this->key.data(), 0, this->key.size());
    this->key.clear();

    std::memset(this->plaintext.data(), 0, this->plaintext.size());
    this->plaintext.clear();

    std::memset(this->ciphertext.data(), 0, this->ciphertext.size());
    this->ciphertext.clear();
}

void AESCBC::initializeEncrypt() {
    auto ivLen = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    this->iv.resize(ivLen);

    const long unsigned int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    RAND_poll();

    // Generate random IV
    if(ivType) {
        this->iv.assign(this->iv.size(), 0);
    }
    else {
        if(RAND_bytes(this->iv.data(), ivLen) != 1) {
            throw std::runtime_error("Error generating IV");
        }
    }

    //check overflow
    if(plaintext.size() > INT_MAX - blockSize)
        throw std::runtime_error("PInteger overflow (file too large)");
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("Error creating new context");

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        throw std::runtime_error("Error initializing encryption");

    ciphertext.resize(plaintext.size() + blockSize);
}

void AESCBC::updateEncrypt() {
    int len;
    if(EVP_EncryptUpdate(ctx, ciphertext.data() + processedBytes, &len, plaintext.data() + processedBytes, plaintext.size() - processedBytes) != 1)
        throw std::runtime_error("Error updating encryption");
    processedBytes += len;
}

void AESCBC::finalizeEncrypt() {
    int len = 0;
    if(EVP_EncryptFinal_ex(ctx, ciphertext.data() + processedBytes, &len) != 1)
        throw std::runtime_error("Error finalizing encryption");
    processedBytes += len;
    ciphertext.erase(ciphertext.begin() + processedBytes, ciphertext.end());

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();
}

void AESCBC::initializeDecrypt(){
    plaintext.clear();
    plaintext.resize(ciphertext.size());

    if(iv.empty() || key.empty() || ciphertext.empty())
        throw std::runtime_error("Error initializing decryption");

    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("Error creating new context");

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        throw std::runtime_error("Error initializing decryption");

    processedBytes = 0;
}

void AESCBC::updateDecrypt() {
    int len = 0;
    if(EVP_DecryptUpdate(ctx, plaintext.data() + processedBytes, &len, ciphertext.data() + processedBytes, ciphertext.size() - processedBytes) != 1)
        throw std::runtime_error("Error updating decryption");
    processedBytes += len;
}

void AESCBC::finalizeDecrypt() {
    int len = 0;
    if(EVP_DecryptFinal_ex(ctx, plaintext.data() + processedBytes*sizeof(uint8_t), &len) != 1){
        auto error = ERR_get_error();
        std::cout << "Error code: " << error << std::endl;

        char errorString[1024];
        ERR_error_string(error, errorString);

        std::cout << "Error string: " << errorString << std::endl;

        ERR_print_errors_fp(stderr);

        if(error == EVP_R_BAD_DECRYPT)
            throw std::runtime_error("Error finalizing decryption: Bad decrypt");
        else
            throw std::runtime_error("Error finalizing decryption");
    }
    processedBytes += len;
}

void AESCBC::run(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, std::vector<uint8_t>& iv) {
    if(this->type == ENCRYPT) {
        this->plaintext.resize(input.size());

        std::copy(input.begin(), input.end(), this->plaintext.begin());

        initializeEncrypt();
        std::copy(this->iv.begin(), this->iv.end(), iv.begin());

        updateEncrypt();
        finalizeEncrypt();
        
        output.resize(this->ciphertext.size());
        std::copy(this->ciphertext.begin(), this->ciphertext.end(), output.begin());
        output.shrink_to_fit();
    }
    else if(type == DECRYPT) {
        this->ciphertext.resize(input.size());
        std::copy(input.begin(), input.end(), this->ciphertext.begin());

        this->iv.resize(iv.size());
        std::copy(iv.begin(), iv.end(), this->iv.begin());

        initializeDecrypt();
        updateDecrypt();
        finalizeDecrypt();

        output.resize(this->plaintext.size());
        std::copy(this->plaintext.begin(), this->plaintext.end(), output.begin());
        output.shrink_to_fit();
    } else {
        throw std::runtime_error("Invalid type");
    }
}