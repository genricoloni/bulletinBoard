#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 

#include <thread>
#include <csignal>
#include <vector>

#include "../const.hpp"
#include "worker.hpp"




class Server {
public:
    Server(int port, int workerCount, volatile sig_atomic_t* signal_caught);
    ~Server();


    void acceptClient();

    void startListening();

    FileRWLock* fileLock;

    std::vector<message>* messages;
    FileRWLock* messageLock;



private:
    int socket;

    int port;
    int workerCount;

    job_t* jobs;

    std::vector<Worker*> workers;
    std::vector<std::thread> workerThreads;

    volatile sig_atomic_t* signal_caught;
    
    struct sockaddr_in serverAddress;
    struct sockaddr_in userAddress;
    int userAddressLength;
    int userSocket;

    void handleClient();
    void stopListening();



    sockaddr_in address(); //server address
};