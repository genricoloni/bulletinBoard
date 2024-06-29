#include <vector>
#include <iostream>
#include <stdexcept>

#include <openssl/evp.h>

class SHA512 {
public:
    SHA512();
    SHA512(const SHA512&) = delete;
    ~SHA512();

    static void generateHash(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<uint8_t>& digest, unsigned int& digestLength);
    static bool verifyHash(const unsigned char* inputBuffer, size_t inputBufferLength, const unsigned char* digest);
};