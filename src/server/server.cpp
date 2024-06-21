#include "../server/server.hpp"

Server::Server(int port, int workerCount) {
    this->port = port;
    this->workerCount = workerCount;
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
    clientAddressLength = sizeof(clientAddress);
    clientSocket = accept(socket, (struct sockaddr *) &clientAddress, (socklen_t *) &clientAddressLength);

    if (clientSocket < 0) {
        perror("Error on accept");
        exit(1);
    }

    //handleClient();
}
