#include "worker.hpp"

Worker::Worker(job_t* job){
    this->job = job;

}

Worker::~Worker(){
    return;
}

void Worker::handleClient(){
    //accept client
    clientSocket = accept(clientSocket, (struct sockaddr *) &clientAddress, &clientAddressLength);
    if (clientSocket < 0) {
        perror("Error on accept");
        exit(1);
    }

    //read from client
    char buffer[256];
    bzero(buffer, 256);
    int n = read(clientSocket, buffer, 255);
    if (n < 0) {
        perror("Error reading from socket");
        exit(1);
    }
    printf("Message from client: %s\n", buffer);

    //write to client
    n = write(clientSocket, "I got your message", 18);
    if (n < 0) {
        perror("Error writing to socket");
        exit(1);
    }

    close(clientSocket);
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
            printf("Queue size: %d\n", job->queue.size());
        #endif

        //get job
        clientSocket = job->queue.front();
        job->queue.erase(job->queue.begin());

        printf("Handling client\n");
        printf("Client socket: %d\n", clientSocket);
        printf("Client address: %s\n", inet_ntoa(clientAddress.sin_addr));
        printf("Client port: %d\n", ntohs(clientAddress.sin_port));
    }
}