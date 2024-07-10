#include "TOPTGenerator.hpp"
#include <stdexcept>
#include <fstream> // Add this line to include the <fstream> header

TOTPGenerator::TOTPGenerator() {
    //open file and read secret key
    std::ifstream
    file("res/keys/private/challengeKey.key", std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open secret key file");
    }

    std::streampos size = file.tellg();

    secretKey_.resize(size);

    file.seekg(0, std::ios::beg);

    if (!file.read(secretKey_.data(), size)) {
        throw std::runtime_error("Failed to read secret key");
    }

    file.close();

    if (secretKey_.empty()) {
        throw std::runtime_error("Secret key is empty");
    }

    if (secretKey_.size() < 16) {
        throw std::runtime_error("Secret key is too short");
    }

    #ifdef DEBUG
    printf("Secret key: %s\n", secretKey_.c_str());
    #endif

       
}

std::string TOTPGenerator::generateTOTP(uint64_t timeStep) const {
    time_t now = time(nullptr);
    uint64_t timeCounter = now / timeStep;

    std::vector<uint8_t> counterBytes(sizeof(timeCounter));
    for (ssize_t i = 0; i < sizeof(timeCounter); ++i) {
        counterBytes[sizeof(timeCounter) - i - 1] = (timeCounter >> (i * 8)) & 0xFF;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, HMAC_HASH(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    if (EVP_DigestUpdate(ctx, secretKey_.c_str(), secretKey_.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest");
    }

    if (EVP_DigestUpdate(ctx, counterBytes.data(), counterBytes.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest");
    }

    uint8_t hash[EVP_MAX_MD_SIZE];

    unsigned int hashLength;

    if (EVP_DigestFinal_ex(ctx, hash, &hashLength) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(ctx);

    uint32_t offset = hash[hashLength - 1] & 0x0F;
    uint32_t binary = (hash[offset] & 0x7F) << 24 | (hash[offset + 1] & 0xFF) << 16 | (hash[offset + 2] & 0xFF) << 8 | (hash[offset + 3] & 0xFF);

    uint32_t otp = binary % 1000000;

    //if the otp is less than 6 digits, add zeros to the left
    if (otp < 100000) {
        return "0" + std::to_string(otp);
    }

    return std::to_string(otp);
}