#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <algorithm>

#include "../const.hpp"

struct sessionMessage {

    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> hmac;

    sessionMessage() {}
    sessionMessage(int ciphertext_size);
    sessionMessage(const std::vector<uint8_t>& session_key, const std::vector<uint8_t>& hmac_key, const std::vector<uint8_t>& plaintext);
    ~sessionMessage();
    bool verify_HMAC(const unsigned char* key);
    uint16_t decrypt(const std::vector<uint8_t>& key, std::vector<unsigned char>& plaintext);
    std::vector<uint8_t> serialize() const;
    static sessionMessage deserialize(const std::vector<uint8_t>& buffer, const int ciphertext_size);
    static int get_size(int plaintext_size);
    void print() const;
};