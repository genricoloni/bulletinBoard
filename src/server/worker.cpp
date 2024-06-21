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
        
        //get the corresponding sockaddr_in
        userAddressLength = sizeof(struct sockaddr_in);
        getpeername(userSocket, (struct sockaddr *) &userAddress, &userAddressLength);


    }
}