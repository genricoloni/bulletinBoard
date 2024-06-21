#include <vector>
#include <openssl/evp.h>

class DiffieHellman {

    EVP_PKEY *mDHParameters;

public:
    DiffieHellman();
    ~DiffieHellman();

    EVP_PKEY* generateEPHKey();
    void generateSharedSecret(EVP_PKEY *privateKey, EVP_PKEY *peerEPHKey, std::vector<unsigned char> &sharedSecret);

    static std::vector<uint8_t>serializePublicKey(EVP_PKEY *key);
    static EVP_PKEY *deserializePublicKey(const std::vector<uint8_t> &serializedKey, int keyLength);
};