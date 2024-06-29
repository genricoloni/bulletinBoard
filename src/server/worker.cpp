#include "worker.hpp"

Worker::Worker(job_t* job){
    this->job = job;

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
        ssize_t n = recv(userSocket, &buffer.data()[receivedBytes], bufferSize - receivedBytes, 0);

        if (n < 0) 
            throw std::runtime_error("Error reading from socket");
        
        if (n == 0) 
            throw std::runtime_error("Connection closed");

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

    DiffieHellman* dh = new DiffieHellman();
    EVP_PKEY* EPH_KEY = nullptr;
    EVP_PKEY* peerEPHKey = nullptr;

    try{
        dh = new DiffieHellman();

        //generate EPH key
        EPH_KEY = dh->generateEPHKey();

        //deserialize peer EPH key
        peerEPHKey = dh->deserializeKey(m1.EPHKey, m1.EPHkeyLength);
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
        SHA512::generateHash(sharedSecret.data(), sharedSecretSize, keys, keySize);

        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();
    } catch(const std::exception &e) {
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        std::memset(keys.data(), 0, keys.size());
        keys.clear();

        EVP_PKEY_free(EPH_KEY);

        throw e;
    }

    #ifdef DEBUG
        printf("Session keys generated\n");
    #endif

    std::memcpy(this->sessionKey.data(), keys.data(), keys.size()/2 * sizeof(uint8_t));
    std::memcpy(this->hmacKey.data(), keys.data() + keys.size()/2, HMAC_DIGESTS_SIZE * sizeof(uint8_t));
};