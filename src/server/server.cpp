#include "../server/server.hpp"

Server::Server(int port, int workerCount, volatile sig_atomic_t* signal_caught) {
    this->port = port;
    this->workerCount = workerCount;
    this->signal_caught = signal_caught;

    jobs = new job_t();
    jobs->isDone = false;

    FileRWLock* fileLock = new FileRWLock("res/users/users.txt");
    this->fileLock = fileLock;

    BulletinBoardSystem* bbs = new BulletinBoardSystem();
    this->bbs = bbs;

    FileRWLock* messageLock = new FileRWLock();
    this->messageLock = messageLock;
    
    return;
}

Server::~Server() {
    return;
}

void Server::startListening() {
    //create socket
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) {
        perror("Error opening socket");
        exit(1);
    }

    //bind socket
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(this->port);

    const int enable = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");


    if (bind(socket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error on binding");
        printf("Port: %d\n", this->port);
        exit(1);
    }

    //listen
    if (listen(socket, 5) < 0) {
        perror("Error on listen");
        exit(1);
    }
}

void Server::acceptClient() {

    printf("Creating workers\n");

    
    jobs->isDone = false;

    workers.reserve(workerCount);
    workerThreads.reserve(workerCount);


    for (int i = 0; i < workerCount; i++) {
        //new worker
        Worker* worker = new Worker(jobs, fileLock, bbs, messageLock);
        workers.push_back(worker);
        workerThreads.emplace_back([&worker]() { worker->workerMain(); });
    
    }

    struct sockaddr_in userAddress;
    socklen_t userAddressLength = sizeof(struct sockaddr_in);
    int userSocket = -1;

    while(true){
        //set up the select call
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);

        //timer for timeout
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        //select call
        int retval = select(socket + 1, &readfds, nullptr, nullptr, &tv);

        if(retval == -1){
            perror("Error on select");
            std::cin >> retval;
            exit(1);
        }
        if(retval == 0){
            //timeout
            continue;
        }
        userSocket = accept(socket, (struct sockaddr *) &userAddress, &userAddressLength);
        if (userSocket < 0) {
            perror("Error on accept");
            exit(1);
        }

        #ifdef DEBUG
        //print the port of the client
        printf("Client port: %d\n", ntohs(userAddress.sin_port));
        printf("Client address: %s\n", inet_ntoa(userAddress.sin_addr));
        #endif



        jobs->queue.push_back(userSocket);
        
  

        jobs->cv.notify_one();

    }

}