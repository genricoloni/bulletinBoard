#include <vector>
#include <cstring>
#include <openssl/hmac.h>
#include <stdexcept>

#include "../const.hpp"

class HMAC {
    unsigned char* mKey;

public:
    HMAC(const unsigned char* key);
    HMAC(const HMAC&) = delete;
    ~HMAC();

    void generateHMAC(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<uint8_t>& digest, unsigned int& digestLength);
    bool verifyHMAC(const unsigned char* inputBuffer, size_t inputBufferLength, std::vector<unsigned char>& digest);
};

