#include <iostream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/bn.h> 
#include <openssl/err.h> // Add this line to include the header file for ERR_get_error
#include "diffieHellman.hpp"

BIGNUM* generateRandomNumber(int numBits) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* num = BN_new();

    if (ctx == NULL || num == NULL) {
        std::cerr << "Error creating random number" << std::endl;
        exit(1);
    }

    if (!BN_rand(num, numBits, 0, 0)) {
        std::cerr << "Error generating random number" << std::endl;
        exit(1);
    }

    BN_CTX_free(ctx);
    return num;
}

DiffieHellman::DiffieHellman() {
    //generate DH parameters for 2048 bit key using openssl
    static unsigned char dh2048_p[] = {
        0xDB, 0x53, 0x9C, 0x0B, 0xF0, 0xAE, 0x71, 0x24, 0x9B, 0xB8,
        0x43, 0x75, 0x67, 0x79, 0xD0, 0xD9, 0x44, 0xF8, 0x57, 0xD0,
        0x29, 0x28, 0x22, 0xF2, 0xD3, 0x36, 0xE4, 0x2C, 0xDC, 0x2B,
        0x5C, 0x22, 0x36, 0x13, 0x88, 0xFB, 0xBF, 0x22, 0x39, 0x19,
        0x6B, 0x02, 0x28, 0x89, 0x75, 0xE8, 0xE2, 0x0C, 0x81, 0xC1,
        0xBF, 0x28, 0x5D, 0xEF, 0x75, 0x4A, 0x49, 0x08, 0x3A, 0x6F,
        0xA5, 0xAE, 0xBF, 0xEA, 0x47, 0xD5, 0x7C, 0xAE, 0x13, 0x44,
        0x5A, 0xCC, 0xDF, 0x61, 0xC6, 0xA6, 0xE3, 0xE2, 0x53, 0xED,
        0x34, 0xF9, 0x75, 0x61, 0x49, 0x95, 0x1E, 0x2B, 0x90, 0x4D,
        0x9B, 0x72, 0x79, 0xC0, 0x36, 0x77, 0x06, 0xE9, 0x13, 0x08,
        0x84, 0x19, 0xC9, 0x62, 0xA3, 0xC1, 0x86, 0x13, 0xF0, 0xF9,
        0xA1, 0x54, 0x73, 0xB8, 0x54, 0xFC, 0x83, 0xFD, 0x51, 0x51,
        0xCE, 0x66, 0x33, 0xBA, 0x11, 0x10, 0xFB, 0x38, 0xD1, 0x03,
        0x71, 0x22, 0xD4, 0x34, 0xA6, 0x21, 0x49, 0x2A, 0x75, 0xCF,
        0xC1, 0xFE, 0xF0, 0xB0, 0x33, 0xA4, 0x0E, 0x34, 0xCB, 0xA0,
        0x4A, 0x8B, 0xA8, 0x65, 0x6C, 0x7C, 0xF9, 0xB8, 0x71, 0xBE,
        0xC6, 0xB5, 0xB3, 0x1E, 0x3B, 0xD3, 0x2B, 0x9B, 0xEC, 0x7D,
        0xD5, 0x4C, 0xBA, 0x18, 0xBB, 0xEE, 0xAB, 0x06, 0x67, 0x86,
        0x0B, 0x16, 0xAF, 0xDC, 0xBE, 0xB3, 0x09, 0x0B, 0x32, 0xDE,
        0x68, 0x1F, 0x81, 0x68, 0xC9, 0x56, 0x16, 0xA0, 0xC4, 0x4E,
        0x70, 0xA9, 0xB8, 0xD4, 0x71, 0x80, 0xF4, 0x56, 0xA4, 0x5E,
        0xFA, 0x5F, 0x9E, 0x48, 0x72, 0x22, 0xDB, 0xB6, 0x1E, 0x56,
        0x3A, 0xA5, 0xE9, 0x46, 0xF3, 0x1B, 0x3F, 0xA9, 0xA4, 0x0E,
        0xD4, 0x29, 0x0B, 0x6E, 0x4B, 0x08, 0x9C, 0x5F, 0x61, 0x5A,
        0xC9, 0x94, 0xCB, 0xA4, 0x16, 0x45, 0x52, 0x07, 0xFD, 0xBD,
        0x81, 0x1B, 0x34, 0x9D, 0xDE, 0x6B
    };
	static unsigned char dh2048_g[]={
		0x02,
		};
	DH *dh = DH_new();

    if (dh == NULL) {
        throw std::runtime_error("Error creating DH structure");
    }

    BIGNUM* p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    BIGNUM* g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);

    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        std::cerr << "Error setting DH parameters" << std::endl;
        DH_free(dh);
        
        if(p != NULL) BN_free(p);
        if(g != NULL) BN_free(g);

        throw std::runtime_error("Error setting DH parameters");
    }

    mDHParameters = EVP_PKEY_new();
    if (!mDHParameters) {
        std::cerr << "Error creating EVP_PKEY structure" << std::endl;
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        throw std::runtime_error("Error creating EVP_PKEY structure");
    }

    if(EVP_PKEY_set1_DH(mDHParameters, dh) != 1) {
        std::cerr << "Error setting DH parameters" << std::endl;
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        EVP_PKEY_free(mDHParameters);
        throw std::runtime_error("Error setting DH parameters");
    }

    DH_free(dh);
}

DiffieHellman::~DiffieHellman() {
    EVP_PKEY_free(mDHParameters);
}

EVP_PKEY *DiffieHellman::generateEPHKey() {

    EVP_PKEY_CTX *DH_ctx = EVP_PKEY_CTX_new(mDHParameters, NULL);
    if(!DH_ctx)
        throw std::runtime_error("Error creating DH context");
    EVP_PKEY *ephemeral_key = NULL;

    if(EVP_PKEY_keygen_init(DH_ctx) != 1) {
        EVP_PKEY_CTX_free(DH_ctx);
        throw std::runtime_error("Error initializing keygen");
        }

    if(EVP_PKEY_keygen(DH_ctx, &ephemeral_key) != 1) {
        EVP_PKEY_CTX_free(DH_ctx);
        throw std::runtime_error("Error generating key");
        }
    
    EVP_PKEY_CTX_free(DH_ctx);
    return ephemeral_key;

}

void DiffieHellman::generateSharedSecret(EVP_PKEY *privateKey, EVP_PKEY *peerEPHKey, std::vector<unsigned char> &sharedSecret) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, NULL);

    if (ctx == NULL) {
        std::cerr << "Error creating EVP_PKEY_CTX structure" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    if(EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "Error initializing derivation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }
    if(EVP_PKEY_derive_set_peer(ctx, peerEPHKey) <= 0) {
        std::cerr << "Error setting peer key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }
    size_t sharedSecretSize = sharedSecret.size();
    EVP_PKEY_derive(ctx, NULL, &sharedSecretSize);

    sharedSecret.resize(int(sharedSecretSize));

    if(EVP_PKEY_derive(ctx, sharedSecret.data(), &sharedSecretSize) <= 0) {
        std::cerr << "Error deriving shared secret" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }
    EVP_PKEY_CTX_free(ctx);
}

std::vector<uint8_t> DiffieHellman::serializeKey(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        std::cerr << "Error creating BIO structure" << std::endl;
        exit(1);
    }

    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        std::cerr << "Error writing public key to BIO" << std::endl;
        BIO_free(bio);
        exit(1);
    }

    int serializedKeyLength = BIO_pending(bio);
    std::vector<uint8_t> serializedKey(serializedKeyLength);

    if(serializedKey.empty()) {
        std::cerr << "Error allocating memory for serialized key" << std::endl;
        BIO_free(bio);
        exit(1);
    }

    if(BIO_read(bio, serializedKey.data(), serializedKeyLength) != serializedKeyLength) {
        std::cerr << "Error reading serialized key" << std::endl;
        BIO_free(bio);
        exit(1);
    }

    BIO_free(bio);
    return serializedKey;
}

EVP_PKEY *DiffieHellman::deserializeKey(uint8_t* serializedKey, int keyLength) {
    BIO *bio = BIO_new_mem_buf(serializedKey, keyLength);
    if (!bio) {
        std::cerr << "Error creating BIO structure" << std::endl;
        throw std::runtime_error("Error creating BIO structure");
    }

    EVP_PKEY *key = NULL;
    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    if(key == NULL) {
        std::cerr << "Error reading public key from BIO" << std::endl;
        BIO_free(bio);
        throw std::runtime_error("Error reading public key from BIO");
    }

    BIO_free(bio);
    return key;
}