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

struct ProtocolM3 {
    uint32_t iv_length;
    std::vector<uint8_t> iv;
    uint32_t encSignatureSize;
    std::vector<uint8_t> encSignature;
    uint32_t mode;

    ProtocolM3() : iv_length(0), encSignatureSize(0) {}

    ProtocolM3(std::vector<uint8_t> iv, std::vector<uint8_t> encSignature, uint32_t mode) {
        this->iv_length = iv.size();
        this->iv.resize(this->iv_length);
        std::memcpy(this->iv.data(), iv.data(), this->iv_length);

        this->encSignatureSize = encSignature.size();
        this->encSignature.resize(this->encSignatureSize);
        std::memcpy(this->encSignature.data(), encSignature.data(), this->encSignatureSize);

        this->mode = mode;
    }

    static int GetSize() {
        int size = 0;

        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    std::vector<uint8_t> serialize() const{
        std::vector<uint8_t> buffer(ProtocolM3::GetSize());
        size_t position = 0;

        uint32_t iv_length_network = htonl(this->iv_length);
        std::memcpy(buffer.data(), &iv_length_network, sizeof(iv_length_network));
        position += sizeof(iv_length_network);

        std::memcpy(buffer.data() + position, this->iv.data(), this->iv_length);
        position += this->iv_length;

        uint32_t encSignatureSizeNetwork = htonl(this->encSignatureSize);
        std::memcpy(buffer.data() + position, &encSignatureSizeNetwork, sizeof(encSignatureSizeNetwork));
        position += sizeof(encSignatureSizeNetwork);

        std::memcpy(buffer.data() + position, this->encSignature.data(), this->encSignatureSize);
        position += this->encSignatureSize;

        uint32_t modeNetwork = htonl(this->mode);
        std::memcpy(buffer.data() + position, &modeNetwork, sizeof(modeNetwork));

        return buffer;
    }

    static ProtocolM3 deserialize(std::vector<uint8_t> buffer) {
        ProtocolM3 m3;

        size_t position = 0;

        uint32_t iv_length_network = 0;
        std::memcpy(&iv_length_network, buffer.data(), sizeof(iv_length_network));
        m3.iv_length = ntohl(iv_length_network);
        position += sizeof(iv_length_network);

        m3.iv.resize(m3.iv_length);
        std::memcpy(m3.iv.data(), buffer.data() + position, m3.iv_length);
        position += m3.iv_length;

        uint32_t encSignatureSizeNetwork = 0;
        std::memcpy(&encSignatureSizeNetwork, buffer.data() + position, sizeof(encSignatureSizeNetwork));
        m3.encSignatureSize = ntohl(encSignatureSizeNetwork);
        position += sizeof(encSignatureSizeNetwork);

        m3.encSignature.resize(m3.encSignatureSize);
        std::memcpy(m3.encSignature.data(), buffer.data() + position, m3.encSignatureSize);
        position += m3.encSignatureSize;

        uint32_t mode = 0;
        std::memcpy(&mode, buffer.data() + position, sizeof(mode));
        m3.mode = ntohl(mode);
                
        return m3;
    }
        
};
struct ProtocolM4Reg_Usr {
    // this struct only contains username and email for the registration
    uint32_t userSize;
    std::string username;
    uint32_t emailSize;
    std::string email;

    // Constructor with default sizes for username and email
    ProtocolM4Reg_Usr() : username(USER_MAX_SIZE, '\0'), email(MAIL_MAX_SIZE, '\0') {}

    ProtocolM4Reg_Usr(std::string username, std::string email) {
        this->username = username;
        this->email = email;
        this->userSize = username.size();
        this->emailSize = email.size();
    }

    static int GetSize() {
        return sizeof(uint32_t) + USER_MAX_SIZE + sizeof(uint32_t) + MAIL_MAX_SIZE;
    }

    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> buffer(ProtocolM4Reg_Usr::GetSize());
        size_t position = 0;

        uint32_t userSizeNetwork = htonl(this->userSize);
        std::memcpy(buffer.data(), &userSizeNetwork, sizeof(userSizeNetwork));
        position += sizeof(userSizeNetwork);

        std::memcpy(buffer.data() + position, this->username.c_str(), this->userSize);
        position += this->userSize;

        uint32_t emailSizeNetwork = htonl(this->emailSize);
        std::memcpy(buffer.data() + position, &emailSizeNetwork, sizeof(emailSizeNetwork));
        position += sizeof(emailSizeNetwork);

        std::memcpy(buffer.data() + position, this->email.c_str(), this->emailSize);

        return buffer;
    }

    static ProtocolM4Reg_Usr deserialize(std::vector<uint8_t> buffer) {
        ProtocolM4Reg_Usr m4;

        size_t position = 0;

        uint32_t userSizeNetwork = 0;
        std::memcpy(&userSizeNetwork, buffer.data(), sizeof(userSizeNetwork));
        m4.userSize = ntohl(userSizeNetwork);
        position += sizeof(userSizeNetwork);

        m4.username.resize(m4.userSize);
        std::memcpy(&m4.username[0], buffer.data() + position, m4.userSize);
        position += m4.userSize;

        uint32_t emailSizeNetwork = 0;
        std::memcpy(&emailSizeNetwork, buffer.data() + position, sizeof(emailSizeNetwork));
        m4.emailSize = ntohl(emailSizeNetwork);
        position += sizeof(emailSizeNetwork);

        m4.email.resize(m4.emailSize);
        std::memcpy(&m4.email[0], buffer.data() + position, m4.emailSize);

        return m4;
    }
};



struct ProtocolM4Response{
    uint32_t response;

    ProtocolM4Response() : response(0) {}

    ProtocolM4Response(uint32_t response) : response(response) {}

    static int GetSize() {
        return sizeof(uint32_t);
    }

    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> buffer(ProtocolM4Response::GetSize());
        size_t position = 0;

        uint32_t responseNetwork = htonl(this->response);
        std::memcpy(buffer.data(), &responseNetwork, sizeof(responseNetwork));

        return buffer;
    }

    static ProtocolM4Response deserialize(std::vector<uint8_t> buffer) {
        ProtocolM4Response m4;

        size_t position = 0;

        uint32_t responseNetwork = 0;
        std::memcpy(&responseNetwork, buffer.data(), sizeof(responseNetwork));
        m4.response = ntohl(responseNetwork);

        return m4;
    }

};

struct PasswordMessage {
    uint8_t password[PASSWORD_MAX_SIZE];
    uint32_t counter;

    PasswordMessage() {}

    PasswordMessage(const char* password, uint32_t counter) 
    {
        memset(this->password, 0, PASSWORD_MAX_SIZE);
        memcpy(this->password, password, PASSWORD_MAX_SIZE);
        this->counter = counter;
    }

    void serialize(std::vector<uint8_t>& buffer) 
    {
        ssize_t position = 0;

        std::memcpy(buffer.data(), this->password, PASSWORD_MAX_SIZE);
        position += PASSWORD_SIZE;

        this->counter = htonl(this->counter);
        #ifdef DEBUG
        std::cout << "Counter: " << this->counter << std::endl;
        std::cout << "Counter Network: " << htonl(this->counter) << std::endl;
        #endif
        std::memcpy(buffer.data() + position, &this->counter, sizeof(uint32_t));
    }

    static PasswordMessage deserialize(const std::vector<uint8_t>& buffer) 
    {
        PasswordMessage passwordMessage;

        ssize_t position = 0;

        std::memcpy(passwordMessage.password, buffer.data(), PASSWORD_MAX_SIZE);
        position += PASSWORD_SIZE;

        std::memcpy(&passwordMessage.counter, buffer.data() + position, sizeof(uint32_t));

        return passwordMessage;
    }
};