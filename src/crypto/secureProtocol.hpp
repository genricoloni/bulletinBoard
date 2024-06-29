#include <string>
#include <limits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector> // Add this include

#include <arpa/inet.h>
#include <openssl/rand.h>

#include "../const.hpp"

struct ProtocolM1 {
    uint32_t EPHkeyLength;
    uint8_t EPHKey[EPH_KEY_SIZE];

    ProtocolM1() : EPHkeyLength(0) {
        memset(EPHKey, 0, EPH_KEY_SIZE);
    }

    ProtocolM1(std::vector<uint8_t>& ephKey, int keyLength) {
        //data sanitization
        if (keyLength > EPH_KEY_SIZE) {
            throw std::invalid_argument("Key length is too large");
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

    static ProtocolM1 deserialize(std::vector<uint8_t>& buffer) {
        ProtocolM1 m1;

        int position = 0;
        uint32_t EPHkeySizeNetwork = 0;

        std::memcpy(&EPHkeySizeNetwork, buffer.data() + position, sizeof(EPHkeySizeNetwork));
        m1.EPHkeyLength = ntohl(EPHkeySizeNetwork);
        position += sizeof(EPHkeySizeNetwork);

        std::memset(m1.EPHKey, 0, sizeof(EPHKey));
        std::memcpy(m1.EPHKey, buffer.data() + position, sizeof(m1.EPHKey));
        position += sizeof(m1.EPHKey) * EPH_KEY_SIZE;

        return m1;
    }
};

struct ProtocolM2 {

    std::vector<uint8_t> EPHKey;
    uint32_t EPHKeyLength;
    std::vector<uint8_t> IV;
    uint32_t IVLength;
    std::vector<uint8_t> encryptedSignature;
    uint32_t encryptedSignatureLength;

    ProtocolM2() {
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

    ProtocolM2 (std::vector<uint8_t>EPHKey, std::vector<uint8_t>IV, std::vector<uint8_t>encryptedSignature) {
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
        std::vector<uint8_t> buffer(ProtocolM2::GetSize());
        size_t position = 0;

        uint32_t EPHKeyLengthNetwork = htonl(this->EPHKeyLength);
        std::memcpy(buffer.data() + position, &EPHKeyLengthNetwork, sizeof(EPHKeyLengthNetwork));
        position += sizeof(EPHKeyLengthNetwork);

        std::memcpy(buffer.data() + position, this->EPHKey.data(), this->EPHKeyLength);
        position += this->EPHKeyLength;

        uint32_t IVLengthNetwork = htonl(this->IVLength);
        std::memcpy(buffer.data() + position, &IVLengthNetwork, sizeof(IVLengthNetwork));
        position += sizeof(IVLengthNetwork);

        std::memcpy(buffer.data() + position, this->IV.data(), this->IVLength);
        position += this->IVLength;

        uint32_t encryptedSignatureLengthNetwork = htonl(this->encryptedSignatureLength);
        std::memcpy(buffer.data() + position, &encryptedSignatureLengthNetwork, sizeof(encryptedSignatureLengthNetwork));
        position += sizeof(encryptedSignatureLengthNetwork);

        std::memcpy(buffer.data() + position, this->encryptedSignature.data(), this->encryptedSignatureLength);

        return buffer;
        }

    static ProtocolM2 deserialize(std::vector<uint8_t> buffer) {

        ProtocolM2 m2;

        size_t position = 0;

        uint32_t EPHKeyLengthNetwork = 0;
        std::memcpy(&EPHKeyLengthNetwork, buffer.data() + position, sizeof(EPHKeyLengthNetwork));
        m2.EPHKeyLength = ntohl(EPHKeyLengthNetwork);
        position += sizeof(EPHKeyLengthNetwork);

        m2.EPHKey.resize(m2.EPHKeyLength);
        std::memcpy(m2.EPHKey.data(), buffer.data() + position, m2.EPHKeyLength);
        position += m2.EPHKeyLength;

        uint32_t IVLengthNetwork = 0;
        std::memcpy(&IVLengthNetwork, buffer.data() + position, sizeof(IVLengthNetwork));
        m2.IVLength = ntohl(IVLengthNetwork);
        position += sizeof(IVLengthNetwork);

        m2.IV.resize(m2.IVLength);
        std::memcpy(m2.IV.data(), buffer.data() + position, m2.IVLength);
        position += m2.IVLength;

        uint32_t encryptedSignatureLengthNetwork = 0;
        std::memcpy(&encryptedSignatureLengthNetwork, buffer.data() + position, sizeof(encryptedSignatureLengthNetwork));
        m2.encryptedSignatureLength = ntohl(encryptedSignatureLengthNetwork);
        position += sizeof(encryptedSignatureLengthNetwork);

        m2.encryptedSignature.resize(m2.encryptedSignatureLength);
        std::memcpy(m2.encryptedSignature.data(), buffer.data() + position, m2.encryptedSignatureLength);

        return m2;
    }
};