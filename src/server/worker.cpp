#include "worker.hpp"

Worker::Worker(job_t* job){
    this->job = job;
    this->iv.resize(AES_BLOCK_SIZE);
    this->hmacKey.resize(SESSION_KEY_LENGTH);
    this->sessionKey.resize(SESSION_KEY_LENGTH);

}

Worker::~Worker(){
    return;
}

void Worker::handleUser(){
    //accept user
    userSocket = accept(userSocket, (struct sockaddr *) &userAddress, &userAddressLength);
    if (userSocket < 0) {
        perror("Error on accept");
        exit(1);
    }

    //read from user
    char buffer[256];
    bzero(buffer, 256);
    int n = read(userSocket, buffer, 255);
    if (n < 0) {
        perror("Error reading from socket");
        exit(1);
    }
    printf("Message from user: %s\n", buffer);

    //write to user
    n = write(userSocket, "I got your message", 18);
    if (n < 0) {
        perror("Error writing to socket");
        exit(1);
    }

    close(userSocket);
}

void Worker::workerMain(){
    while(true){
        //wait for job


        std::unique_lock<std::mutex> lock(job->mutex);
        job->cv.wait(lock, [&]{ return !job->queue.empty() || job->isDone; });

        if(job->isDone){
            printf("Job is done\n");
            return;
        }
        //print some about the queue
        #ifdef DEBUG
            printf("Handling user\n");
            printf("user port: %d\n", ntohs(userAddress.sin_port));
            printf("user address: %s\n", inet_ntoa(userAddress.sin_addr));

        #endif

        //get job
        userSocket = job->queue.front();
        job->queue.erase(job->queue.begin());

        printf("Handling user\n");
        
        try
        {
            initiateProtocol();
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
        


    }


}

ssize_t Worker::receiveMessage(std::vector<uint8_t>& buffer, ssize_t bufferSize) {
    ssize_t receivedBytes = 0;

    while (receivedBytes < bufferSize) {
        ssize_t n = recv(userSocket, reinterpret_cast<unsigned char*>(&buffer.data()[receivedBytes]), bufferSize - receivedBytes, 0);

        if (n < 0) 
            throw std::runtime_error("Error reading from socket");
        
        if (n == 0) 
            throw std::runtime_error("Connection closed");

        receivedBytes += n;
    }
    
        return receivedBytes;
}

ssize_t Worker::workerSend(const std::vector<uint8_t>& buffer) {
    ssize_t sentBytes = 0;
    ssize_t bufferSize = buffer.size();

    while (sentBytes < bufferSize) {
        ssize_t n = send(userSocket, reinterpret_cast<const unsigned char*>(&buffer.data()[sentBytes]), bufferSize - sentBytes, 0);

        if(sentBytes == -1 && (errno == EPIPE || errno == ECONNRESET)) {
            //connection closed
            char message[sizeof("Client disconnected (socket: )") + sizeof(int)] = {0};
            sprintf(message, "Client disconnected (socket: %d)", userSocket);
            throw std::runtime_error(message);
        }

        if(sentBytes == -1) {
            throw std::runtime_error("Error sending message to client");
        }
        sentBytes += n;
    }

    return sentBytes;
}

ssize_t Worker::workerReceive(std::vector<uint8_t>& buffer, ssize_t bufferSize) {
    ssize_t receivedBytes = 0;

    while (receivedBytes < bufferSize) {
        ssize_t n = recv(userSocket, reinterpret_cast<unsigned char*>(&buffer.data()[receivedBytes]), bufferSize - receivedBytes, 0);

        if(receivedBytes == -1)
            throw std::runtime_error("Error reading from socket");

        if(receivedBytes == 0){
            char message[sizeof("Client disconnected (socket: )") + sizeof(int)] = {0};
            sprintf(message, "Client disconnected (socket: %d)", userSocket);
            throw std::runtime_error(message);
        }

        receivedBytes += n;
    }
    
    return receivedBytes;
}

void Worker::initiateProtocol() {
    //allocate space for message M1
    std::vector<uint8_t> serializedM1(ProtocolM1::GetSize());

    try {
        //receive M1
        this->receiveMessage(serializedM1, ProtocolM1::GetSize());
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        throw std::runtime_error("Error receiving message from client");
    }

    #ifdef DEBUG
        printf("Received M1 from client %d\n", ntohs(userAddress.sin_port));
    #endif

    //deserialize M1
    ProtocolM1 m1 = ProtocolM1::deserialize(serializedM1);

    DiffieHellman* dh = nullptr;
    EVP_PKEY* EPH_KEY = nullptr;
    EVP_PKEY* peerEPHKey = nullptr;

    try{
        dh = new DiffieHellman();

        //generate EPH key
        EPH_KEY = dh->generateEPHKey();

        //deserialize peer EPH key
        peerEPHKey = DiffieHellman::deserializeKey(m1.EPHKey, m1.EPHkeyLength);
    } catch (const std::exception &e) {
        if (dh != nullptr) {
            delete dh;
        }
        if (EPH_KEY != nullptr) {
            EVP_PKEY_free(EPH_KEY);
        }
        if (peerEPHKey != nullptr) {
            EVP_PKEY_free(peerEPHKey);
        }
        throw e;
    }

    #ifdef DEBUG
        printf("Received EPH key\n");
    #endif

    //generate shared secret
    std::vector<uint8_t> sharedSecret;
    size_t sharedSecretSize;

    try {
        dh->generateSharedSecret(EPH_KEY, peerEPHKey, sharedSecret, sharedSecretSize);

        EVP_PKEY_free(peerEPHKey);

        delete dh;
        dh = nullptr;
    } catch(const std::exception &e) {
        
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        if (dh != nullptr) {
            delete dh;
        }

        EVP_PKEY_free(EPH_KEY);
        EVP_PKEY_free(peerEPHKey);

        throw e;
    }

    #ifdef DEBUG
        printf("Shared secret generated\n");
    #endif

    //generate session hmac key
    std::vector<uint8_t> keys;
    uint32_t keySize;

    try {
        #ifdef DEBUG
            printf("Generating session keys\n");
            //print address of sharedSecret
            printf("Address of sharedSecret: %p\n", sharedSecret.data());
        #endif
        SHA512::generateHash(reinterpret_cast<const unsigned char*>(sharedSecret.data()), sharedSecret.size(), keys, keySize);

        #ifdef DEBUG
            printf("Session keys generated\n");
        #endif
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();
    } catch(const std::exception &e) {
        #ifdef DEBUG
            std::cerr << e.what() << std::endl;
        #endif
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        std::memset(keys.data(), 0, keys.size());
        keys.clear();

        EVP_PKEY_free(EPH_KEY);

        throw e;
    }

    #ifdef DEBUG
        //print some address about keys and session keys
        printf("Address of keys: %p\n", keys.data());
        printf("Address of session keys: %p\n", sessionKey.data());

    #endif

    std::memcpy(this->sessionKey.data(), keys.data(), (keys.size()/2) * sizeof(uint8_t));

    #ifdef DEBUG
        printf("Session keys copied 1\n");
    #endif

    std::memcpy(this->hmacKey.data(), keys.data() + ((keys.size()/2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));

    #ifdef DEBUG
        printf("Session keys copied\n");
    #endif

    std::memset(keys.data(), 0, keys.size());
    keys.clear();

    #ifdef DEBUG
        printf("Session keys cleared\n");
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
        throw e;
    }

    EVP_PKEY_free(EPH_KEY);

    #ifdef DEBUG
        printf("EPH key serialized\n");
    #endif

    auto EPHKeyBufferSize = m1.EPHkeyLength + serializedEPHKey.size();
    std::vector<uint8_t> EPHKeyBuffer(EPHKeyBufferSize);
    std::memcpy(EPHKeyBuffer.data(), m1.EPHKey, m1.EPHkeyLength);
    std::memcpy(EPHKeyBuffer.data() + m1.EPHkeyLength, serializedEPHKey.data(), serializedEPHKey.size());

    std::vector<unsigned char> signature;
    RSASignature* rsa = nullptr;

    try {
        rsa = new RSASignature(serverPrivateKeyPath, "");

        signature = rsa->sign(EPHKeyBuffer);

        delete rsa;
        rsa = nullptr;

        #ifdef DEBUG
            printf("Signed\n");
        printf("Verifying signature...\n");

        rsa = new RSASignature("", "res/keys/public/server.pem");

        if (!rsa->verify(EPHKeyBuffer, signature)) {
            printf("Signature verification failed\n");
            throw std::runtime_error("Signature verification failed");
        } else {
            printf("Signature verified\n");
        }
        #endif


    } catch (const std::exception &e) {
        #ifdef DEBUG
            std::cerr << e.what() << std::endl;
        #endif
        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        if (rsa != nullptr) {
            delete rsa;
        }

        throw e;
    }

    #ifdef DEBUG
        printf("Signature generated\n");
    #endif

    std::vector<uint8_t>iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t>cipherText;

    AESCBC* enc = nullptr;

    try {
        enc = new AESCBC(ENCRYPT, sessionKey);
        enc->run(signature, cipherText, iv);

        delete enc;
        enc = nullptr;

        std::memset(signature.data(), 0, signature.size());
        signature.clear();
    } catch (const std::exception &e) {
        if (enc != nullptr) 
            delete enc;

        std::memset(iv.data(), 0, iv.size());
        iv.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        throw e;      
    }

    #ifdef DEBUG
        printf("Signature encrypted\n");
    #endif

    try {
        ProtocolM2 m2(serializedEPHKey, iv, cipherText);
        std::vector<uint8_t> serializedM2 = m2.serialize();

        workerSend(serializedM2);

        std::memset(iv.data(), 0, iv.size());
        iv.clear();

        std::memset(cipherText.data(), 0, cipherText.size());
        cipherText.clear();

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();
    } catch (const std::exception &e) {
        std::memset(iv.data(), 0, iv.size());
        iv.clear();

        std::memset(cipherText.data(), 0, cipherText.size());
        cipherText.clear();

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        throw e;
    }

    #ifdef DEBUG
        printf("Sent M2 to client %d\n", ntohs(userAddress.sin_port));
    #endif
    
    std::vector<uint8_t> serializedM3(ProtocolM3::GetSize());

    try{
        this->receiveMessage(serializedM3, ProtocolM3::GetSize());
    }
    catch(const std::exception &e){
        std::cerr << e.what() << '\n';
        EPHKeyBuffer.clear();
        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        throw std::runtime_error("Error receiving message from client");
    }

    #ifdef DEBUG
        printf("Received M3 from client %d\n", ntohs(userAddress.sin_port));
    #endif

    try {
        ProtocolM3 m3 = ProtocolM3::deserialize(serializedM3);

        if (m3.mode == LOGIN_CODE) {
            //login
            if (!login()) {
                throw std::runtime_error("Login failed");
            }
        } 
        if (m3.mode == REGISTER_CODE) {
            //register
            if (!registerUser()) {
                throw std::runtime_error("Register failed");
            }
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        throw std::runtime_error("Error handling client request");
    }

};

bool Worker::login() {
    return true;
}

bool Worker::registerUser() {
    bool success = false;
    //receive message with username and email
    std::vector<uint8_t> serializedM4Reg_Usr(ProtocolM4Reg_Usr::GetSize());

    try {
        this->receiveMessage(serializedM4Reg_Usr, ProtocolM4Reg_Usr::GetSize());
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

    #ifdef DEBUG
        printf("Received M4 from client %d\n", ntohs(userAddress.sin_port));
    #endif

    //deserialize message
    ProtocolM4Reg_Usr m4Reg_Usr = ProtocolM4Reg_Usr::deserialize(serializedM4Reg_Usr);

    #ifdef DEBUG
        printf("Deserialized M4\n");
        printf("Username: %s\n", m4Reg_Usr.username.c_str());
        printf("Email: %s\n", m4Reg_Usr.email.c_str());
    #endif

    //check if username is already in use
    if (checkUsername(m4Reg_Usr.username)) {
        #ifdef DEBUG
            printf("Username already in use\n");
        #endif

        ProtocolM4Response response(USR_ALREADY_TAKEN);
        std::vector<uint8_t> serializedResponse = response.serialize();

        try {
            workerSend(serializedResponse);
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return false;
        }


        return false;
    }

    #ifdef DEBUG
        printf("Username not in use\n");
    #endif

    //check if email is already in use
    if (checkEmail(m4Reg_Usr.email)) {
        #ifdef DEBUG
            printf("Email already in use\n");
        #endif

        ProtocolM4Response response(MAIL_ALREADY_TAKEN);
        std::vector<uint8_t> serializedResponse = response.serialize();
        
        try {
            workerSend(serializedResponse);
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return false;
        }
        
        return false;
    }

    #ifdef DEBUG
        printf("Email not in use\n");
    #endif

    //send response to client
    ProtocolM4Response response(ACK);

    std::vector<uint8_t> serializedResponse = response.serialize();

    try {
        workerSend(serializedResponse);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

    //receive message with password
    std::vector<uint8_t> buffer(sessionMessage::get_size(PWD_MESSAGE1_SIZE));

    try {
        this->receiveMessage(buffer, sessionMessage::get_size(PWD_MESSAGE1_SIZE));
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

    #ifdef DEBUG
        printf("Received password from client %d\n", ntohs(userAddress.sin_port));
    #endif

    sessionMessage message = sessionMessage::deserialize(buffer, PWD_MESSAGE1_SIZE);
    std::memset(buffer.data(), 0, buffer.size());
    buffer.clear();

    #ifdef DEBUG
        printf("Deserialized password message\n");
    #endif

    std::vector<uint8_t> plaintext(PWD_MESSAGE1_SIZE);
    message.decrypt(this->sessionKey, plaintext);

    #ifdef DEBUG
        printf("Decrypted password message\n");
    #endif

    PasswordMessage pwdMessage = PasswordMessage::deserialize(plaintext);

    #ifdef DEBUG
        printf("Deserialized password message\n");
    #endif

    counter = 1;

    #ifdef DEBUG
        printf("Received password message\n");
        printf("Counter Network: %d\n", pwdMessage.counter);
        printf("Counter : %d\n", htonl(pwdMessage.counter));
    #endif

    checkCounter(ntohl(pwdMessage.counter));



    std::string password(pwdMessage.password, pwdMessage.password + 30);

    #ifdef DEBUG
    //print the hex of the password
    for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
        printf("%02x", pwdMessage.password[i]);
    }
    printf("\n");
    #endif
    
    //



    return true;

}

void Worker::checkCounter(uint32_t counter) {
    if (this->counter  != counter) {
        throw std::runtime_error("Counter mismatch");
    }
    this->counter = counter;

}

bool Worker::checkUsername(const std::string& username) {
    //open the file
    std::ifstream file("res/users/users.txt");

    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        //split the line until the first ,
        std::string delimiter = ",";
        std::string user = line.substr(0, line.find(delimiter));

        if (user == username) {
            file.close();
            return true;
        }
    }

    file.close();
    return false;
}

bool Worker::checkEmail(const std::string& email) {
    //open the file
    std::ifstream file("res/users/users.txt");

    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        //split the line until the first ,
        std::string delimiter = ",";
        std::string user = line.substr(0, line.find(delimiter));

        //split the line until the second ,
        line = line.substr(line.find(delimiter) + 1);
        std::string mail = line.substr(0, line.find(delimiter));

        if (mail == email) {
            file.close();
            return true;
        }
    }

    file.close();
    return false;
}