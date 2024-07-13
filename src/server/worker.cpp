#include "worker.hpp"

Worker::Worker(job_t* job, FileRWLock* fileLock, BulletinBoardSystem* bbs, FileRWLock* messageLock){
    this->job = job;
    this->iv.resize(AES_BLOCK_SIZE);
    this->hmacKey.resize(SESSION_KEY_LENGTH);
    this->sessionKey.resize(SESSION_KEY_LENGTH);
    this->fileLock = fileLock;
    this->bbs = bbs;
    this->messageLock = messageLock;

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
    {
        std::unique_lock<std::mutex> lock(job->mutex);
        job->cv.wait(lock, [&](){return !job->queue.empty();});

        if(job->isDone){
            return;
        }

        userSocket = job->queue.front();
        job->queue.erase(job->queue.begin());
    
    }

    #ifdef DEBUG
        printf("DEBUG>> Worker %d handling client\n", ntohs(userAddress.sin_port));
    #endif

    try {
        initiateProtocol();
        waitForRequest();

    } catch (const std::exception &e) {
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
        printf("DEBUG>> Received M1 from client %d\n", ntohs(userAddress.sin_port));
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
        printf("DEBUG>> Received EPH key\n");
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
        printf("DEBUG>> Shared secret generated\n");
    #endif

    //generate session hmac key
    std::vector<uint8_t> keys;
    uint32_t keySize;

    try {
        #ifdef DEBUG
            printf("DEBUG>> Generating session keys\n");
            //print address of sharedSecret
            printf("DEBUG>> Address of sharedSecret: %p\n", sharedSecret.data());
        #endif
        SHA512::generateHash(reinterpret_cast<const unsigned char*>(sharedSecret.data()), sharedSecret.size(), keys, keySize);

        #ifdef DEBUG
            printf("DEBUG>> Session keys generated\n");
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
        printf("DEBUG>> Address of keys: %p\n", keys.data());
        printf("DEBUG>> Address of session keys: %p\n", sessionKey.data());

    #endif

    std::memcpy(this->sessionKey.data(), keys.data(), (keys.size()/2) * sizeof(uint8_t));

    #ifdef DEBUG
        printf("DEBUG>> Session keys copied 1\n");
    #endif

    std::memcpy(this->hmacKey.data(), keys.data() + ((keys.size()/2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));

    #ifdef DEBUG
        printf("DEBUG>> Session keys copied\n");
    #endif

    std::memset(keys.data(), 0, keys.size());
    keys.clear();

    #ifdef DEBUG
        printf("DEBUG>> Session keys cleared\n");
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
        printf("DEBUG>> EPH key serialized\n");
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
            printf("DEBUG>> Signed\n");
            printf("DEBUG>> Verifying signature...\n");

        rsa = new RSASignature("", "res/keys/public/server.pem");

        if (!rsa->verify(EPHKeyBuffer, signature)) {
            printf("DEBUG>> signature verification failed\n");
            throw std::runtime_error("Signature verification failed");
        } else {
            printf("DEBUG>> Signature verified\n");
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
        printf("DEBUG>> Signature generated\n");
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
        printf("DEBUG>> Signature encrypted\n");
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
        printf("DEBUG>> Sent M2 to client %d\n", ntohs(userAddress.sin_port));
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
        printf("DEBUG>> Received M3 from client %d\n", ntohs(userAddress.sin_port));
    #endif

    try {
        ProtocolM3 m3 = ProtocolM3::deserialize(serializedM3);

        if (m3.mode == LOGIN_CODE) {
            //login
            if (!login()) {
                throw std::runtime_error("Login failed");
            }
        } 
        else if (m3.mode == REGISTER_CODE) {
            //register
            if (!registerUser()) {
                throw std::runtime_error("Register failed");
            }

            //after registration, handle the login request
            if (!login()) {
                throw std::runtime_error("Login failed");
            }
    } else {
        std::memset(serializedM3.data(), 0, serializedM3.size());
        serializedM3.clear();

        throw std::runtime_error("Invalid mode");
    }
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        throw std::runtime_error("Error handling client request");
    }
    
    #ifdef DEBUG
        printf("DEBUG>> Client request handled\n");
    #endif

    std::memset(serializedM3.data(), 0, serializedM3.size());
    serializedM3.clear();

    
};

bool Worker::login() {
    bool success = false;

    //receive message with username and empty email
    std::vector<uint8_t> userMessage(ProtocolM4Reg_Usr::GetSize());

    try {
        this->receiveMessage(userMessage, ProtocolM4Reg_Usr::GetSize());
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

    #ifdef DEBUG
        printf("DEBUG>> Received M4 from client\n");
    #endif

    ProtocolM4Reg_Usr m4Reg_Usr = ProtocolM4Reg_Usr::deserialize(userMessage);

    #ifdef DEBUG
        printf("DEBUG>> Deserialized M4\n");
        printf("Username: %s\n", m4Reg_Usr.username.c_str());
        printf("Email: %s\n", m4Reg_Usr.email.c_str());
    #endif

    //check if username is in use
    //take read lock
    if(!fileLock->openForRead()){
        std::cerr << "Error opening file for read\n";
        return false;
    } else {

        if (!checkUsername(m4Reg_Usr.username)) {
            fileLock->closeForRead();
            #ifdef DEBUG
                printf("Username not found\n");
            #endif

            ProtocolM4Response response(USR_NOT_FOUND);
            std::vector<uint8_t> serializedResponse = response.serialize();

            try {
                workerSend(serializedResponse);
            } catch (const std::exception &e) {
                std::cerr << e.what() << '\n';
                return false;
            }

            return false;
        }
        fileLock->closeForRead();
    }

    //send ACK and wait for password
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
        printf("DEBUG>> Received password from client\n");
    #endif

    sessionMessage message = sessionMessage::deserialize(buffer, PWD_MESSAGE1_SIZE);

    std::memset(buffer.data(), 0, buffer.size());
    buffer.clear();

    #ifdef DEBUG
        printf("DEBUG>> Deserialized password message\n");
    #endif

    std::vector<uint8_t> plaintext(PWD_MESSAGE1_SIZE);
    message.decrypt(this->sessionKey, plaintext);

    #ifdef DEBUG
        printf("DEBUG>> Decrypted password message\n");
    #endif

    PasswordMessage pwdMessage = PasswordMessage::deserialize(plaintext);

    #ifdef DEBUG
        printf("DEBUG>> Deserialized password message\n");
    #endif

    #ifdef DEBUG
        printf("DEBUG>> Received password: \n");
        for(int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
            printf("%02x", pwdMessage.password[i]);
        }
        printf("\n");
    #endif

    //lock the file for reading
    if(!fileLock->openForRead()){
        std::cerr << "Error opening file for read\n";
        return false;
    } else {

        if (!checkPassword(m4Reg_Usr.username, pwdMessage.password)) {
            #ifdef DEBUG
                printf("Password mismatch\n");
            #endif

            std::memset(pwdMessage.password, 0, HASHED_PASSWORD_SIZE);
            std::memset(m4Reg_Usr.username.data(), 0, m4Reg_Usr.username.size());
            std::memset(m4Reg_Usr.email.data(), 0, m4Reg_Usr.email.size());
            m4Reg_Usr.username.clear();
            m4Reg_Usr.email.clear();

            ProtocolM4Response response(WRONG_PASSWORD);
            std::vector<uint8_t> serializedResponse = response.serialize();

            try {
                workerSend(serializedResponse);
            } catch (const std::exception &e) {
                std::cerr << e.what() << '\n';
                return false;
            }

            //clear the response message
            std::memset(serializedResponse.data(), 0, serializedResponse.size());
            serializedResponse.clear();

            fileLock->closeForRead();
            return false;
        } 
        fileLock->closeForRead();

    }

    #ifdef DEBUG
        printf("DEBUG>> Password correct\n");
    #endif

    std::memset(pwdMessage.password, 0, HASHED_PASSWORD_SIZE);
    std::memset(m4Reg_Usr.username.data(), 0, m4Reg_Usr.username.size());
    std::memset(m4Reg_Usr.email.data(), 0, m4Reg_Usr.email.size());
    m4Reg_Usr.username.clear();
    m4Reg_Usr.email.clear();

    ProtocolM4Response ack(ACK);

    std::vector<uint8_t> serializedAck = ack.serialize();

    try {
        workerSend(serializedAck);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

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
        printf("DEBUG>> Received M4 from client %d\n", ntohs(userAddress.sin_port));
    #endif

    //deserialize message
    ProtocolM4Reg_Usr m4Reg_Usr = ProtocolM4Reg_Usr::deserialize(serializedM4Reg_Usr);

    #ifdef DEBUG
        printf("DEBUG>> Deserialized M4\n");
        printf("Username: %s\n", m4Reg_Usr.username.c_str());
        printf("Email: %s\n", m4Reg_Usr.email.c_str());
    #endif

    //check if username is already in use
    if (!fileLock->openForRead()) {
        #ifdef DEBUG
            printf("DEBUG>> Error opening file for read\n");
        #endif
        std::cerr << "Error opening file for read\n";
        return false;
    } else {
        #ifdef DEBUG
            printf("DEBUG>> Checking username\n");
        #endif
        if (checkUsername(m4Reg_Usr.username)) {
            #ifdef DEBUG
                printf("Username already in use\n");
            #endif
            #ifdef DEBUG
                fileLock->printReaders();
                printf("DEBUG>> Closed file for read username\n");
            #endif

            ProtocolM4Response response(USR_ALREADY_TAKEN);
            std::vector<uint8_t> serializedResponse = response.serialize();

            try {
                workerSend(serializedResponse);
            } catch (const std::exception &e) {
                std::cerr << e.what() << '\n';
                return false;
            }

            fileLock->closeForRead();

            return false;
        }
        fileLock->closeForRead();


    }

    #ifdef DEBUG
        printf("DEBUG>> Username not in use\n");
    #endif

    //check if email is already in use
    if(!fileLock->openForRead()){
        std::cerr << "Error opening file for read\n";
        return false;
    } else {
        if (checkEmail(m4Reg_Usr.email)) {
            #ifdef DEBUG
                printf("Email already in use\n");
            #endif
            fileLock->closeForRead();

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
        fileLock->closeForRead();

    }

    #ifdef DEBUG
        printf("DEBUG>> Email not in use\n");
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
        printf("DEBUG>> Received password from client %d\n", ntohs(userAddress.sin_port));
    #endif

    sessionMessage message = sessionMessage::deserialize(buffer, PWD_MESSAGE1_SIZE);
    std::memset(buffer.data(), 0, buffer.size());
    buffer.clear();

    #ifdef DEBUG
        printf("DEBUG>> Deserialized password message\n");
    #endif

    std::vector<uint8_t> plaintext(PWD_MESSAGE1_SIZE);
    message.decrypt(this->sessionKey, plaintext);

    #ifdef DEBUG
        printf("DEBUG>> Decrypted password message\n");
    #endif

    PasswordMessage pwdMessage = PasswordMessage::deserialize(plaintext);

    #ifdef DEBUG
        printf("DEBUG>> Deserialized password message\n");
    #endif

    counter = 1;

    #ifdef DEBUG
        printf("DEBUG>> Received password message\n");
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
    
    TOTPGenerator totp;
    
    std::string totpCode = totp.generateTOTP(30);

    #ifdef DEBUG
        printf("DEBUG>> TOTP code: %s\n", totpCode.c_str());
    #endif

    printf("TOTP code: %s\n", totpCode.c_str());

    //wait for client to send OTP
    std::vector<uint8_t> serializedOTP(sessionMessage::get_size(OTP_SIZE));

    try {
        this->receiveMessage(serializedOTP, sessionMessage::get_size(OTP_SIZE));
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }

    #ifdef DEBUG
        printf("DEBUG>> Received OTP from client %d\n", ntohs(userAddress.sin_port));
    #endif

    sessionMessage otpMessage = sessionMessage::deserialize(serializedOTP, OTP_SIZE);

    std::memset(serializedOTP.data(), 0, serializedOTP.size());
    serializedOTP.clear();

    #ifdef DEBUG
        printf("DEBUG>> Deserialized OTP message\n");
    #endif

    std::vector<uint8_t> otpPlaintext(OTP_SIZE);
    otpMessage.decrypt(this->sessionKey, otpPlaintext);

    #ifdef DEBUG
        printf("DEBUG>> Decrypted OTP message\n");
    #endif

    for(int i = 0; i < OTP_SIZE; i++) {
        if (otpPlaintext[i] != totpCode[i]) {
            #ifdef DEBUG
                printf("OTP mismatch\n");
            #endif

            std::memset(otpPlaintext.data(), 0, otpPlaintext.size());
            otpPlaintext.clear();

            std::memset(m4Reg_Usr.username.data(), 0, m4Reg_Usr.username.size());
            std::memset(m4Reg_Usr.email.data(), 0, m4Reg_Usr.email.size());
            m4Reg_Usr.username.clear();
            m4Reg_Usr.email.clear();

            std::memset(pwdMessage.password, 0, HASHED_PASSWORD_SIZE);
            std::memset(password.data(), 0, password.size());
            password.clear();

            ProtocolM4Response response(OTP_MISMATCH);
            std::vector<uint8_t> serializedResponse = response.serialize();

            try {
                workerSend(serializedResponse);
            } catch (const std::exception &e) {
                std::cerr << e.what() << '\n';
                return false;
            }

            //clear the response message
            std::memset(serializedResponse.data(), 0, serializedResponse.size());
            serializedResponse.clear();
            
            return false;
        }
    }


    #ifdef DEBUG
        printf("DEBUG>> Local OTP: %s\n", totpCode.c_str());
        printf("Received OTP: %s\n", std::string(otpPlaintext.begin(), otpPlaintext.end()).c_str());
    #endif


    #ifdef DEBUG
        printf("DEBUG>> Sent response to client %d\n", ntohs(userAddress.sin_port));
    #endif


    //write user to file
    if(!fileLock->openForWrite()){
        std::cerr << "Error opening file for write\n";
        return false;
    } else {
        if (!writeUser(m4Reg_Usr.username, m4Reg_Usr.email, pwdMessage.password)) {
            std::cerr << "Error writing user to file\n";
            return false;
        }
    }

    //send response to client
    ProtocolM4Response result = ProtocolM4Response(ACK);

    std::vector<uint8_t> serializedResult = result.serialize();

    try {
        workerSend(serializedResult);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return false;
    }
        

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

bool Worker::writeUser(const std::string& username, const std::string& email, const uint8_t* password){
    std::ofstream file("res/users/users.txt", std::ios::app);

    #ifdef DEBUG
        printf("DEBUG>> Writing user to file\n");
    #endif
    if (!file.is_open()) {
        return false;
    }

    file << username << "," << email << ",";
    #ifdef DEBUG
        printf("DEBUG>> Wrote username and email\n");
    #endif
    for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
        file << std::hex << std::setw(2) << std::setfill('0') << (int)password[i];
    }
    #ifdef DEBUG
        printf("DEBUG>> Wrote password\n");
    #endif

    file << std::endl;


    file.close();
    return true;
}

bool Worker::checkPassword(const std::string& username, const uint8_t* password) {
    //open the file
    std::ifstream file("res/users/users.txt");

    //convert the password to a string
    std::string pwd;
    for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
        pwd += std::to_string(password[i]);
    }


    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        //split the line until the first ,
        std::string delimiter = ",";
        std::string user = line.substr(0, line.find(delimiter));

        if (user == username) {
            //split the line until the second ,
            line = line.substr(line.find(delimiter) + 1);
            std::string mail = line.substr(0, line.find(delimiter));

            //split the line until the third ,
            line = line.substr(line.find(delimiter) + 1);
            std::uint8_t* pwd = new std::uint8_t[HASHED_PASSWORD_SIZE];
            for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
                std::string byte = line.substr(i * 2, 2);
                pwd[i] = std::stoi(byte, nullptr, 16);
            }


            #ifdef DEBUG
                printf("Password from file: \n");
                for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
                    printf("%02x", pwd[i]);
                }
                printf("\n");
                printf("Password from client: \n");
                for (int i = 0; i < HASHED_PASSWORD_SIZE; i++) {
                    printf("%02x", password[i]);
                }
                printf("\n");
            #endif

            if (std::memcmp(pwd, password, HASHED_PASSWORD_SIZE) == 0) {
                file.close();
                return true;
            }

            delete[] pwd;
        }
    }

    file.close();
    return false;
}

void Worker::waitForRequest(){
    while (true) {
        std::vector<uint8_t> buffer(sessionMessage::get_size(sizeof(uint32_t)));

        #ifdef DEBUG
            printf("DEBUG>> buffer size: %ld\n", buffer.size());
        #endif

        try {
            receiveMessage(buffer, sessionMessage::get_size(sizeof(uint32_t)));
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return;
        }

        sessionMessage sessionMsg = sessionMessage::deserialize(buffer, sizeof(uint32_t));

        #ifdef DEBUG
            printf("DEBUG>> Received session message\n");
        #endif

        std::vector<uint8_t> plaintext(sessionMessage::get_size(sizeof(uint32_t)));
        sessionMsg.decrypt(this->sessionKey, plaintext);


        uint32_t msg = ntohl(*reinterpret_cast<uint32_t*>(plaintext.data()));

        #ifdef DEBUG
            printf("DEBUG>> Received request: %d\n", msg);
        #endif


        switch(msg) {
            case LIST_CODE:
            
                sendAck();
                ListHandler();
                break;

            case ADD_CODE:
                sendAck();
                AddHandler();
                break;

            case GET_CODE:
                #ifdef DEBUG
                    printf("DEBUG>> GET_CODE\n");   
                #endif
                GetHandler();
                break;

            default:
                sendError();
                break;                



        }
    }
}

void Worker::sendAck(){
    ProtocolM4Response ack(ACK);
    std::vector<uint8_t> serializedAck = ack.serialize();

    try {
        workerSend(serializedAck);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    std::memset(serializedAck.data(), 0, serializedAck.size());
    serializedAck.clear();
}

void Worker::sendError(){
    ProtocolM4Response ack(NACK);
    std::vector<uint8_t> serializedAck = ack.serialize();

    try {
        workerSend(serializedAck);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    std::memset(serializedAck.data(), 0, serializedAck.size());
    serializedAck.clear();
}


void Worker::AddHandler() {
    #ifdef DEBUG
        printf("DEBUG>> AddHandler\n");
    #endif
    //prepare a buffer to receive a session message
    std::vector<uint8_t> buffer(sessionMessage::get_size(MAX_MESSAGE_SIZE));

    try {
        receiveMessage(buffer, sessionMessage::get_size(MAX_MESSAGE_SIZE));
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    #ifdef DEBUG
        printf("DEBUG>> Received message\n");
    #endif

    sessionMessage session_msg = sessionMessage::deserialize(buffer, MAX_MESSAGE_SIZE);

    std::vector<uint8_t> plaintext(sessionMessage::get_size(MAX_MESSAGE_SIZE));
    session_msg.decrypt(this->sessionKey, plaintext);



    #ifdef DEBUG
        printf("DEBUG>> Deserialized message\n");
        printf("ID: %d\n", plaintext[0]);
        //address of plaintext[0]
        printf("Address of ID: %p\n", &plaintext[0]);
        void* Daddress = &plaintext[0];
        printf("Author: %s\n", reinterpret_cast<char*>(Daddress + sizeof(uint32_t)));
    #endif

    void* address = &plaintext[0];
    #ifdef DEBUG
        printf("DEBUG>> Address of plaintext: %p\n", address);
    #endif



    std::string author(reinterpret_cast<char*>(address + sizeof(uint32_t)));

    #ifdef DEBUG
        printf("DEBUG>> Author: %s\n", author.c_str());
    #endif


    address = address + sizeof(uint32_t) + NAME_SIZE*sizeof(uint8_t);

    //title
    std::string title(reinterpret_cast<char*>(address));

    #ifdef DEBUG
        printf("DEBUG>> Title: %s\n", title.c_str());
    #endif


    address = address + sizeof(uint8_t) * MAX_TITLE_SIZE;

    //body
    std::string body(reinterpret_cast<char*>(address));

    #ifdef DEBUG
        printf("DEBUG>> Body: %s\n", body.c_str());
        printf("DEBUG>> Message deserialized\n");
    #endif


    message msg = message(plaintext[0], author, title, body);    



    bbs->Add(msg.title, msg.author, msg.body);

    #ifdef DEBUG
        bbs->printHead();
    #endif


    return;



}


void Worker::GetHandler() {
    sendAck();
    #ifdef DEBUG
        printf("DEBUG>> GetHandler\n");
    #endif
    std::vector<uint8_t> buffer(sessionMessage::get_size(sizeof(uint32_t)));
    try {
        receiveMessage(buffer, sessionMessage::get_size(sizeof(uint32_t)));
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    #ifdef DEBUG
        printf("DEBUG>> Received message\n");
    #endif

    sessionMessage session_msg = sessionMessage::deserialize(buffer, sizeof(uint32_t));

    std::vector<uint8_t> plaintext(sessionMessage::get_size(sizeof(uint32_t)));
    session_msg.decrypt(this->sessionKey, plaintext);

    uint32_t id = ntohl(*reinterpret_cast<uint32_t*>(plaintext.data()));

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();

    #ifdef DEBUG
        printf("DEBUG>> Received n: %d\n", id);
    #endif

    //get the message with id = id

    message msg = bbs->Get(id);

    //resize the fields of the message to the maximum size
    std::vector<uint8_t> serializedMsg(MAX_MESSAGE_SIZE);
    int i = 0;

    //id
    std::memcpy(serializedMsg.data() + i, &msg.id, sizeof(uint32_t));
    i += sizeof(uint32_t);

    //author
    std::memcpy(serializedMsg.data() + i, msg.author.c_str(), NAME_SIZE * sizeof(uint8_t));
    i += NAME_SIZE * sizeof(uint8_t);

    //title
    std::memcpy(serializedMsg.data() + i, msg.title.c_str(), MAX_TITLE_SIZE * sizeof(uint8_t));
    i += MAX_TITLE_SIZE * sizeof(uint8_t);

    //body
    std::memcpy(serializedMsg.data() + i, msg.body.c_str(), MAX_BODY_SIZE * sizeof(uint8_t));
    i += MAX_BODY_SIZE * sizeof(uint8_t);




    #ifdef DEBUG
        printf("DEBUG>> Message retrieved\n");
        printf("DEBUG>> ID: %d\n", serializedMsg[0]);
        printf("DEBUG>> Author: %s\n", reinterpret_cast<char*>(serializedMsg.data() + sizeof(uint32_t)));
        printf("DEBUG>> Title: %s\n", reinterpret_cast<char*>(serializedMsg.data() + sizeof(uint32_t) + NAME_SIZE * sizeof(uint8_t)));
        printf("DEBUG>> Body: %s\n", reinterpret_cast<char*>(serializedMsg.data() + sizeof(uint32_t) + NAME_SIZE * sizeof(uint8_t) + MAX_TITLE_SIZE * sizeof(uint8_t)));
    #endif

    //serialize the message
    

    #ifdef DEBUG
        printf("DEBUG>> Message serialized\n");
    #endif

    //create a session message with the serialized message
    sessionMessage session_msg2 = sessionMessage(this->sessionKey, this->hmacKey, serializedMsg);

    std::vector<uint8_t> serializedSessionMessage = session_msg2.serialize();

    #ifdef DEBUG
        printf("DEBUG>> Session message serialized\n");
    #endif

    try {
        workerSend(serializedSessionMessage);
        #ifdef DEBUG
            printf("DEBUG>> Sent message to client\n");
        #endif
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
    serializedSessionMessage.clear();

    std::memset(serializedMsg.data(), 0, serializedMsg.size());
    serializedMsg.clear();

    return;

}

void Worker::ListHandler() {
    std::vector<uint8_t> buffer(sessionMessage::get_size(sizeof(uint32_t)));
    try {
        receiveMessage(buffer, sessionMessage::get_size(sizeof(uint32_t)));
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }

    sessionMessage session_msg = sessionMessage::deserialize(buffer, sizeof(uint32_t));

    std::vector<uint8_t> plaintext(sessionMessage::get_size(sizeof(uint32_t)));
    session_msg.decrypt(this->sessionKey, plaintext);

    uint32_t n = ntohl(*reinterpret_cast<uint32_t*>(plaintext.data()));

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();

    #ifdef DEBUG
        printf("DEBUG>> Received n: %d\n", n);
    #endif

    //sessionMessage session_msg;
    std::vector<message> messages = bbs->List(n);
    uint32_t size = messages.size();
    #ifdef DEBUG
        printf("DEBUG>> MEssages found: %d\n", size);
    #endif
    uint32_t size1 = ntohl(size);
    std::vector<uint8_t> serializedSize(sizeof(size));
    std::memcpy(serializedSize.data(), &size1, sizeof(size1));
    #ifdef EDBUG
        printf("DEBUG>> Serialized size: %d\n", serializedSize.data());
    #endif
    sessionMessage tmp = sessionMessage(this->sessionKey, this->hmacKey, serializedSize);
    std::vector<uint8_t> serializedSessionMessageTmp = tmp.serialize();
    try {
        workerSend(serializedSessionMessageTmp);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }
    // iterate through the messages and serialize them into a single string to send to the client.
    // the messages are separated by a newline character
    // std::string serializedMessages;
    for (int i = 0; i < messages.size(); i++) {
        #ifdef DEBUG
            printf("DEBUG>> Message %d\n", i);
            printf("DEBUG>> ID: %d\n", messages[i].id);
            printf("DEBUG>> Author: %s\n", messages[i].author.c_str());
            printf("DEBUG>> Title: %s\n", messages[i].title.c_str());
            printf("DEBUG>> Body: %s\n", messages[i].body.c_str());
        #endif
        std::vector<uint8_t> serializedMsg(MAX_MESSAGE_SIZE);
        serializedMsg = bbs->serialize(messages[i]);
        
        sessionMessage sessionMsg = sessionMessage(this->sessionKey, this->hmacKey, serializedMsg);
        
        std::vector<uint8_t> serializedSessionMessage1 = sessionMsg.serialize();

        try {
            workerSend(serializedSessionMessage1);
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return;
        }

        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();

        std::memset(serializedMsg.data(), 0, serializedMsg.size());
        serializedMsg.clear();
        
        //serializedMessages += std::string(serializedMsg.begin(), serializedMsg.end());
    }

    #ifdef DEBUG
        printf("DEBUG>> Funziona\n");
    #endif
    return;

    /*std::memset(serializedMessages.data(), 0, serializedMessages.size());
    serializedMessages.clear();*/

    // create a session message with the serialized messages
}