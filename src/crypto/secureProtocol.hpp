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
    uint32_t EPHkeyLength;
    uint8_t EPHKey[EPH_KEY_SIZE];

    protocolM1() {
        memset(EPHKey, 0, EPH_KEY_SIZE);
    }

    protocolM1(std::vector<uint8_t>& ephKey, int keyLength) {
        //data sanitization
        if (keyLength > EPH_KEY_SIZE) {
            throw std::invalid_argument("Key length is too large");
        }

        if (ephKey.size() != keyLength) {
            throw std::invalid_argument("Key length does not match the key size");
        }

        this->EPHkeyLength = keyLength;

        memcpy(this->EPHKey, ephKey.data(), keyLength);
    }

    void serialize(std::vector<uint8_t>& buffer) {
        int position = 0;
        buffer.resize(GetSize());

        uint32_t EPHkeySizeNetwork = htonl(EPHkeyLength);
        std::memcpy(buffer.data() + position, &EPHkeySizeNetwork, sizeof(EPHkeySizeNetwork));
        position += sizeof(EPHkeySizeNetwork);

        std::memcpy(buffer.data() + position, EPHKey, EPHkeyLength);
        position += EPHkeyLength;
    }

    static inline int GetSize() {
        return sizeof(EPHkeyLength) + sizeof(EPHKey);
    }

    protocolM1 deserialize(std::vector<uint8_t>& buffer) {
        protocolM1 m1;

        int position = 0;
        uint32_t EPHkeySizeNetwork = 0;

        std::memcpy(&EPHkeySizeNetwork, buffer.data() + position, sizeof(EPHkeySizeNetwork));
        m1.EPHkeyLength = ntohl(EPHkeySizeNetwork);
        position += sizeof(EPHkeySizeNetwork);

        std::memcpy(m1.EPHKey, 0, sizeof(m1.EPHKey));
        std::memcpy(m1.EPHKey, buffer.data() + position, sizeof(m1.EPHKey));
        position += sizeof(m1.EPHKey) * EPH_KEY_SIZE;

        return m1;
    }
};
