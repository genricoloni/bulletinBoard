#include <iostream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/bn.h> 
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
    static unsigned char dh2236_p[]={
		0x0F,0x52,0xE5,0x24,0xF5,0xFA,0x9D,0xDC,0xC6,0xAB,0xE6,0x04,
		0xE4,0x20,0x89,0x8A,0xB4,0xBF,0x27,0xB5,0x4A,0x95,0x57,0xA1,
		0x06,0xE7,0x30,0x73,0x83,0x5E,0xC9,0x23,0x11,0xED,0x42,0x45,
		0xAC,0x49,0xD3,0xE3,0xF3,0x34,0x73,0xC5,0x7D,0x00,0x3C,0x86,
		0x63,0x74,0xE0,0x75,0x97,0x84,0x1D,0x0B,0x11,0xDA,0x04,0xD0,
		0xFE,0x4F,0xB0,0x37,0xDF,0x57,0x22,0x2E,0x96,0x42,0xE0,0x7C,
		0xD7,0x5E,0x46,0x29,0xAF,0xB1,0xF4,0x81,0xAF,0xFC,0x9A,0xEF,
		0xFA,0x89,0x9E,0x0A,0xFB,0x16,0xE3,0x8F,0x01,0xA2,0xC8,0xDD,
		0xB4,0x47,0x12,0xF8,0x29,0x09,0x13,0x6E,0x9D,0xA8,0xF9,0x5D,
		0x08,0x00,0x3A,0x8C,0xA7,0xFF,0x6C,0xCF,0xE3,0x7C,0x3B,0x6B,
		0xB4,0x26,0xCC,0xDA,0x89,0x93,0x01,0x73,0xA8,0x55,0x3E,0x5B,
		0x77,0x25,0x8F,0x27,0xA3,0xF1,0xBF,0x7A,0x73,0x1F,0x85,0x96,
		0x0C,0x45,0x14,0xC1,0x06,0xB7,0x1C,0x75,0xAA,0x10,0xBC,0x86,
		0x98,0x75,0x44,0x70,0xD1,0x0F,0x20,0xF4,0xAC,0x4C,0xB3,0x88,
		0x16,0x1C,0x7E,0xA3,0x27,0xE4,0xAD,0xE1,0xA1,0x85,0x4F,0x1A,
		0x22,0x0D,0x05,0x42,0x73,0x69,0x45,0xC9,0x2F,0xF7,0xC2,0x48,
		0xE3,0xCE,0x9D,0x74,0x58,0x53,0xE7,0xA7,0x82,0x18,0xD9,0x3D,
		0xAF,0xAB,0x40,0x9F,0xAA,0x4C,0x78,0x0A,0xC3,0x24,0x2D,0xDB,
		0x12,0xA9,0x54,0xE5,0x47,0x87,0xAC,0x52,0xFE,0xE8,0x3D,0x0B,
		0x56,0xED,0x9C,0x9F,0xFF,0x39,0xE5,0xE5,0xBF,0x62,0x32,0x42,
		0x08,0xAE,0x6A,0xED,0x88,0x0E,0xB3,0x1A,0x4C,0xD3,0x08,0xE4,
		0xC4,0xAA,0x2C,0xCC,0xB1,0x37,0xA5,0xC1,0xA9,0x64,0x7E,0xEB,
		0xF9,0xD3,0xF5,0x15,0x28,0xFE,0x2E,0xE2,0x7F,0xFE,0xD9,0xB9,
		0x38,0x42,0x57,0x03,
		};
	static unsigned char dh2236_g[]={
		0x02,
		};
	DH *dh = DH_new();

    if (dh == NULL) {
        std::cerr << "Error creating DH structure" << std::endl;
        exit(1);
    }

    BIGNUM* p = BN_bin2bn(dh2236_p, sizeof(dh2236_p), NULL);
    BIGNUM* g = BN_bin2bn(dh2236_g, sizeof(dh2236_g), NULL);

    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        std::cerr << "Error setting DH parameters" << std::endl;
        DH_free(dh);
        exit(1);
    }

    mDHParameters = EVP_PKEY_new();
    if (mDHParameters == NULL || EVP_PKEY_set1_DH(mDHParameters, dh) != 1) {
        std::cerr << "Error creating EVP_PKEY structure" << std::endl;
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        exit(1);
    }

    DH_free(dh);
}

DiffieHellman::~DiffieHellman() {
    EVP_PKEY_free(mDHParameters);
}

EVP_PKEY *DiffieHellman::generateEPHKey() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mDHParameters, NULL);
    EVP_PKEY *key = NULL;

    if (ctx == NULL) {
        std::cerr << "Error creating EVP_PKEY_CTX structure" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    if ( EVP_PKEY_keygen(ctx, &key) != 1 ) {
        std::cerr << "Error generating EPH key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
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

std::vector<uint8_t> DiffieHellman::serializePublicKey(EVP_PKEY *key) {
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

EVP_PKEY *DiffieHellman::deserializePublicKey(const std::vector<uint8_t> &serializedKey, int keyLength) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        std::cerr << "Error creating BIO structure" << std::endl;
        exit(1);
    }

    EVP_PKEY *key = NULL;
    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(key == NULL) {
        std::cerr << "Error reading public key from BIO" << std::endl;
        BIO_free(bio);
        exit(1);
    }

    BIO_free(bio);
    return key;
}