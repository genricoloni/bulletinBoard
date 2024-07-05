#include "../client/client.hpp"
#include <cstring>




Client::Client(int port) : port(port){
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }


    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP);

    hmacKey.resize(SESSION_KEY_LENGTH);
    sessionKey.resize(SESSION_KEY_LENGTH);

}

Client::~Client() {
    ::close(socket);

    //clean the username
    username = "";
}

void Client::connectToServer() {

    printf("Connecting to server\n");

    if (connect(socket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        
        //call the destructor
        this->~Client();

        exit(1);
    }
    else {
        printf("Connected to server\n");
    }
}

void Client::sendToServer(const std::vector<uint8_t>& message) {
    ssize_t byteSent = 0;
    ssize_t totalByteSent = 0;
    ssize_t messageLength = message.size();

    while (totalByteSent < messageLength) {
        byteSent = send(socket, message.data() + totalByteSent, messageLength - totalByteSent, 0);
        if (byteSent == -1) {
            std::cerr << "Error sending message to server" << std::endl;
            return;
        }
        totalByteSent += byteSent;
    }
}

void Client::receiveFromServer(std::vector<uint8_t>& message) {
    ssize_t byteReceived = 0;
    ssize_t totalByteReceived = 0;
    ssize_t messageLength = message.size();

    while (totalByteReceived < messageLength) {
        byteReceived = recv(socket, message.data() + totalByteReceived, messageLength - totalByteReceived, 0);
        
        if(byteReceived != -1 && byteReceived != 0)
            totalByteReceived += byteReceived;
        

        if(byteReceived == 0)
            throw std::runtime_error("Connection closed by server");
        }
        
        if (byteReceived == -1) {
            throw std::runtime_error("Error receiving message from server");
        }
    }


void Client::initiateProtocol() {
    #ifdef DEBUG
    printf("Initiating communication to create secure connection\n");
    #endif

    //create the DiffieHellman object
    DiffieHellman dh;
    EVP_PKEY *EPH_KEY = nullptr;

    try {
        EPH_KEY = dh.generateEPHKey();
    }
    catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (EPH_KEY != nullptr) {
            EVP_PKEY_free(EPH_KEY);
        }
        throw std::runtime_error("Error generating EPH key");
    }

    //serialize EPHEMERAL KEY

    #ifdef DEBUG
    printf("EPH key generated\n");
    #endif



    std::vector<uint8_t> serializedEPHKey;

    try{
        serializedEPHKey = DiffieHellman::serializeKey(EPH_KEY);
    }
    catch(const std::exception &e){
        EVP_PKEY_free(EPH_KEY);
        
        if (!serializedEPHKey.empty()) {
            std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
            serializedEPHKey.clear();
        }
        throw std::runtime_error("Error serializing EPH key");
    }

    #ifdef DEBUG
    printf("EPH key serialized\n");
    #endif

    ProtocolM1 m1(serializedEPHKey, serializedEPHKey.size());

    std::vector<uint8_t> serializedM1;
    m1.serialize(serializedM1);

    try{
        sendToServer(serializedM1);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(serializedM1.data(), 0, serializedM1.size());
        serializedM1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("M1 sent\n");
    #endif

    std::vector<uint8_t> serializedM2(ProtocolM2::GetSize());

    try {
        receiveFromServer(serializedM2);
    } catch(const std::exception &e) {
        #ifdef DEBUG
            std::cerr << e.what() << std::endl;
        #endif

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(serializedM1.data(), 0, serializedM1.size());
        serializedM1.clear();

        std::memset(serializedM2.data(), 0, serializedM2.size());
        serializedM2.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM2 m2 = ProtocolM2::deserialize(serializedM2);
    serializedM2.clear();

    EVP_PKEY *serverEPHKey = nullptr;
    std::vector<uint8_t> sharedSecret;

    try {
        serverEPHKey = DiffieHellman::deserializeKey(m2.EPHKey.data(), m2.EPHKeyLength);

        dh.generateSharedSecret(EPH_KEY, serverEPHKey, sharedSecret, sharedSecret.size());
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (serverEPHKey != nullptr) {
            EVP_PKEY_free(serverEPHKey);
        }

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        if(serverEPHKey != nullptr) 
            EVP_PKEY_free(serverEPHKey);
        
        throw std::runtime_error("Error generating shared secret");
    }

    #ifdef DEBUG
    //print ifno about sharedSecret
    printf("Shared secret buffer size: %ld\n", sharedSecret.size());
    printf("Shared secret buffer address: %p\n", reinterpret_cast<const unsigned char*>(sharedSecret.data()));
    #endif

    EVP_PKEY_free(serverEPHKey);
    EVP_PKEY_free(EPH_KEY);

    //generate hmac key from shared secret
    std::vector<uint8_t> keys;
    uint32_t keySize;

    try {
        SHA512::generateHash(sharedSecret.data(), sharedSecret.size(), keys, keySize);
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        std::memset(keys.data(), 0, keys.size());
        keys.clear();

        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        throw std::runtime_error("Error generating HMAC key");
    }

    #ifdef DEBUG
    printf("HMAC key generated\n");
    #endif

    std::memcpy(this->sessionKey.data(), keys.data(), (keys.size() / 2) * sizeof(uint8_t));
    std::memcpy(this->hmacKey.data(), keys.data() + (keys.size() / 2)* sizeof(uint8_t), HMAC_DIGEST_SIZE * sizeof(uint8_t));

    std::memset(keys.data(), 0, keys.size());
    keys.clear();

    #ifdef DEBUG
    printf("Session key and HMAC key generated\n");
    #endif

    //prepare <g^a, g^b> for the server
    int EPHKeyBufferLength = m2.EPHKeyLength + serializedEPHKey.size();
    std::vector<uint8_t> EPHKeyBuffer(EPHKeyBufferLength);
    std::memcpy(EPHKeyBuffer.data(), serializedEPHKey.data(), serializedEPHKey.size());
    std::memcpy(EPHKeyBuffer.data() + serializedEPHKey.size(), m2.EPHKey.data(), m2.EPHKeyLength);

    std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
    serializedEPHKey.clear();

    std::vector<uint8_t> signature;

    try {
        char privateKeyPath[] = "res/keys/private/client1.pem";

        RSASignature rsa(privateKeyPath, "");

        signature = rsa.sign(EPHKeyBuffer);

        #ifdef DEBUG
        printf("Signature generated\n");
        #endif
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        throw std::runtime_error("Error generating signature");
    }

    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> encryptedSignature;
    AESCBC* encryptor = nullptr;

    try {
        encryptor = new AESCBC(ENCRYPT, this->sessionKey);
        encryptor->run(signature, encryptedSignature, iv);
        delete encryptor;

        std::memset(signature.data(), 0, signature.size());
        signature.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (encryptor != nullptr) {
            delete encryptor;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        throw std::runtime_error("Error encrypting signature");
    }

    #ifdef DEBUG
    printf("Signature encrypted\n");
    #endif

    std::vector<uint8_t> decryptedSignature;
    AESCBC* decryptor = nullptr;

    try {
        decryptor = new AESCBC(DECRYPT, this->sessionKey);
        decryptor->run(m2.encryptedSignature, decryptedSignature, m2.IV);
        delete decryptor;
        decryptedSignature.resize(DECRYPTED_SIGNATURE_SIZE);
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (decryptor != nullptr) {
            delete decryptor;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();

        throw std::runtime_error("Error decrypting signature");
    }

    //verify the signature
    RSASignature* rsa = nullptr;
    bool verified = true;

    try {
        //retrieve the public key of the server
        char publicKeyPath[] = "res/keys/public/server.pem";

        rsa = new RSASignature("", publicKeyPath);
        verified = rsa->verify(EPHKeyBuffer, decryptedSignature);
        delete rsa;

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (rsa != nullptr) {
            delete rsa;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();

        throw std::runtime_error("Error verifying signature");
    }

    if (!verified) {
        throw std::runtime_error("Signature not verified");
    } else {
        #ifdef DEBUG
        printf("Signature verified\n");
        #endif
    }


};

