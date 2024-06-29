#include <vector>
#include <fstream>
#include <stdexcept>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

class RSASignature {

public:
    RSASignature(const std::string& privateKeyPath, const std::string& publicKeyPath);
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);

private:
    EVP_PKEY* mPrivateKey;
    EVP_PKEY* mPublicKey;
};