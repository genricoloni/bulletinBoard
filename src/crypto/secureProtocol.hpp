#include <string>
#include <limits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector> // Add this include

#include <arpa/inet.h>
#include <openssl/rand.h>

#include "../const.hpp"

struct protocolM1 {
    uint32_t keyLength;
    uint8_t EPHKey[EPH_KEY_SIZE];
    // RSA public key
    uint32_t publicKeyLength;
    uint8_t publicKey[EPH_KEY_SIZE];

    protocolM1() {
        memset(EPHKey, 0, EPH_KEY_SIZE);
    }

    protocolM1(std::vector<uint8_t>& ephKey, int keyLength, uint8_t* publicKey, int publicKeyLength) {
        //data sanitization
        if (keyLength > EPH_KEY_SIZE) {
            throw std::invalid_argument("Key length is too large");
        }

        if (ephKey.size() != keyLength) {
            throw std::invalid_argument("Key length does not match the key size");
        }

        if (publicKeyLength > EPH_KEY_SIZE) {
            throw std::invalid_argument("Public key length is too large");
        }
        
        if (publicKeyLength > EPH_KEY_SIZE) {
            throw std::invalid_argument("Public key length is too large");
        }

        if(publicKey == NULL) {
            throw std::invalid_argument("Public key is NULL");
        }

        this->keyLength = keyLength;
        this->publicKeyLength = publicKeyLength;

        memcpy(this->EPHKey, ephKey.data(), keyLength);
        memcpy(this->publicKey, publicKey, publicKeyLength);

    }

};