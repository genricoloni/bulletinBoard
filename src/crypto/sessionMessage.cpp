
#include "sessionMessage.hpp"
#include "../crypto/AESCBC.hpp"
#include "../crypto/HMAC.hpp" 

sessionMessage::sessionMessage(int ciphertext_size)
{
    iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    ciphertext.resize(ciphertext_size);
    hmac.resize(HMAC_DIGEST_SIZE);
}

sessionMessage::sessionMessage(const std::vector<uint8_t>& session_key, const std::vector<uint8_t>& hmac_key, const std::vector<uint8_t>& plaintext)
{
    iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    AESCBC encrypt(ENCRYPT, session_key);
    encrypt.run(plaintext, ciphertext, iv);

    //concatenate iv and ciphertext
    std::vector<uint8_t> buffer(iv.size() + ciphertext.size());
    std::copy(iv.begin(), iv.end(), buffer.begin());
    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + iv.size());

    //generate HMAC
    HMac hmac(hmac_key.data());
    std::vector<uint8_t> digest;
    unsigned int digest_size = 0;
    hmac.generate(buffer.data(), iv.size() + ciphertext.size(), digest, digest_size);
    this->hmac.resize(digest_size);
    std::copy(digest.begin(), digest.end(), this->hmac.begin());

    std::memset(buffer.data(), 0, buffer.size()*sizeof(uint8_t));
    buffer.clear();

    std::memset(digest.data(), 0, digest.size()*sizeof(uint8_t));
    digest.clear();
}

sessionMessage::~sessionMessage()
{
    std::memset(iv.data(), 0, iv.size()*sizeof(uint8_t));
    iv.clear();

    std::memset(ciphertext.data(), 0, ciphertext.size()*sizeof(uint8_t));
    ciphertext.clear();

    std::memset(hmac.data(), 0, hmac.size()*sizeof(uint8_t));
    hmac.clear();
}

bool sessionMessage::verify_HMAC(const unsigned char* key)
{
    std::vector<uint8_t> buffer(iv.size() + ciphertext.size()*sizeof(uint8_t));
    std::memcpy(buffer.data(), iv.data(), iv.size()*sizeof(uint8_t));
    std::memcpy(buffer.data() + iv.size(), ciphertext.data(), ciphertext.size()*sizeof(uint8_t));

    HMac hmac(key);
    return hmac.verify(buffer.data(), iv.size() + ciphertext.size(), this->hmac);
}

uint16_t sessionMessage::decrypt(const std::vector<uint8_t>& key, std::vector<unsigned char>& plaintext)
{
    AESCBC decrypt(DECRYPT, key);
    decrypt.run(ciphertext, plaintext, iv);

    uint16_t type;
    std::memcpy(&type, plaintext.data(), sizeof(uint16_t));
    return type;
}

std::vector<uint8_t> sessionMessage::serialize() const
{
    ssize_t buffer_size = iv.size() + ciphertext.size() + hmac.size();
    std::vector<uint8_t> buffer(buffer_size);

    ssize_t position = 0;

    std::copy(iv.begin(), iv.end(), buffer.begin() + position);
    position += iv.size();

    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + position);
    position += ciphertext.size();

    std::copy(hmac.begin(), hmac.end(), buffer.begin() + position);

    return buffer;
}

sessionMessage sessionMessage::deserialize(const std::vector<uint8_t>& buffer, const int plaintext_size)
{
    int ciphertextSize = plaintext_size + (EVP_CIPHER_iv_length(EVP_aes_256_cbc())) - (plaintext_size % (EVP_CIPHER_iv_length(EVP_aes_256_cbc())));
    sessionMessage message(ciphertextSize);

    ssize_t position = 0;

    std::copy(buffer.begin(), buffer.begin() + EVP_CIPHER_iv_length(EVP_aes_256_cbc()) * sizeof(uint8_t), message.iv.begin());
    position += EVP_CIPHER_iv_length(EVP_aes_256_cbc());

    std::copy(buffer.begin() + position, buffer.begin() + position + (message.ciphertext.size() * sizeof(uint8_t)), message.ciphertext.begin());
    position += message.ciphertext.size();

    std::memcpy(message.hmac.data(), buffer.data() + position, HMAC_DIGEST_SIZE*sizeof(uint8_t));

    return message;
}

int sessionMessage::get_size(int plaintext_size)
{
    int blockSize = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    int ciphertextSize = (plaintext_size % blockSize == 0) ? plaintext_size : plaintext_size + blockSize - (plaintext_size % blockSize);

    int size = 0;
    size += EVP_CIPHER_iv_length(EVP_aes_256_cbc())*sizeof(uint8_t);
    size += ciphertextSize*sizeof(uint8_t);
    size += HMAC_DIGEST_SIZE*sizeof(uint8_t);

    return size;
}