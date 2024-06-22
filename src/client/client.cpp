#include "../client/client.hpp"
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>



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

void Client::initiateProtocol() {
    #ifdef DEBUG
    printf("Initiating communication to create secure connection\n");
    #endif

    DiffieHellman dh;
    EVP_PKEY *ephKey = NULL;

    try{
        //generate the key
        ephKey = dh.generateEPHKey();
    } catch (const std::exception &e) {
        if (ephKey != NULL) {
            EVP_PKEY_free(ephKey);
        }
        //throw the exception
        throw std::runtime_error(e.what());
    }

    //serialize the key
    std::vector<uint8_t> serializedKey;

    try {
        serializedKey = DiffieHellman::serializePublicKey(ephKey);
    } catch (const std::exception &e) {
        EVP_PKEY_free(ephKey);
        //throw the exception
        
        if(!serializedKey.empty()){
            //clear the memory using memset
            memset(&serializedKey[0], 0, serializedKey.size());
            serializedKey.clear();
        }
        throw std::runtime_error(e.what());
    }

}
