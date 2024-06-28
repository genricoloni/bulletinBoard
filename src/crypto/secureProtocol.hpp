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

struct HandshakeM2 {

    std::vector<uint8_t> EPHKey;
    uint32_t EPHKeyLength;
    std::vector<uint8_t> IV;
    uint32_t IVLength;
    std::vector<uint8_t> encryptedSignature;
    uint32_t encryptedSignatureLength;

    HandshakeM2() {
        EPHKeyLength = 0;
        IVLength = 0;
        encryptedSignatureLength = 0;
    }

    static int GetSize() {

        int size = 0;

        size += EPH_KEY_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    HandshakeM2 (std::vector<uint8_t>EPHKey, std::vector<uint8_t>IV, std::vector<uint8_t>encryptedSignature) {
        this->EPHKeyLength = (unsigned int)EPHKey.size();
        this->IVLength = (unsigned int)IV.size();
        this->encryptedSignatureLength = (unsigned int)encryptedSignature.size();

        this->EPHKey.resize(this->EPHKeyLength);
        std::memcpy(this->EPHKey.data(), EPHKey.data(), this->EPHKeyLength);

        this->IV.resize(this->IVLength);
        std::memcpy(this->IV.data(), IV.data(), this->IVLength);

        this->encryptedSignature.resize(this->encryptedSignatureLength);
        std::memcpy(this->encryptedSignature.data(), encryptedSignature.data(), this->encryptedSignatureLength);
    }

    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> buffer(HandshakeM2::GetSize());
        size_t position = 0;

        uint32_t EPHKeyLengthNetwork = htonl(this->EPHKeyLength);
        std::memcpy(buffer.data() + position, &EPHKeyLengthNetwork, sizeof(EPHKeyLengthNetwork));
        
}
};