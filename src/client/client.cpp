#include "../client/client.hpp"
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>



Client::Client(int port) : port(port){
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }


    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP);

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