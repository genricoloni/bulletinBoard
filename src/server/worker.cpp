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
        ssize_t n = recv(userSocket, buffer.data() + receivedBytes, bufferSize - receivedBytes, 0);

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
    std::vector<uint8_t> serializedM1(HandshakeM2::GetSize());

    try {
        //receive the message M1
        receiveMessage(serializedM1, HandshakeM2::GetSize());
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return;
    }

    //deserialize the message M1
    HandshakeM2 m2 = HandshakeM2::deserialize(serializedM1);

    DiffieHellman* dh = nullptr;

    EVP_PKEY* EPH_KEY = nullptr;
    EVP_PKEY* PEER_EPH_KEY = nullptr;
}