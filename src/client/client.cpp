#include "../client/client.hpp"
#include <cstring>




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

void Client::sendToServer(const std::vector<uint8_t>& message) {
    ssize_t byteSent = 0;
    ssize_t totalByteSent = 0;
    ssize_t messageLength = message.size();

    while (totalByteSent < messageLength) {
        byteSent = send(socket, message.data() + totalByteSent, messageLength - totalByteSent, 0);
        if (byteSent == -1) {
            std::cerr << "Error sending message to server" << std::endl;
            return;
        }
        totalByteSent += byteSent;
    }
}

void Client::initiateProtocol() {
    #ifdef DEBUG
    printf("Initiating communication to create secure connection\n");
    #endif

    //create the DiffieHellman object
    DiffieHellman dh;
    EVP_PKEY *EPH_KEY = nullptr;

    try {
        EPH_KEY = dh.generateEPHKey();
    }
    catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (EPH_KEY != nullptr) {
            EVP_PKEY_free(EPH_KEY);
        }
        throw std::runtime_error("Error generating EPH key");
    }

    //serialize EPHEMERAL KEY

    #ifdef DEBUG
    printf("EPH key generated\n");
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
        throw std::runtime_error("Error serializing EPH key");
    }

    #ifdef DEBUG
    printf("EPH key serialized\n");
    #endif

    ProtocolM1 m1(serializedEPHKey, serializedEPHKey.size());

    std::vector<uint8_t> serializedM1;
    m1.serialize(serializedM1);

    try{
        sendToServer(serializedM1);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(serializedM1.data(), 0, serializedM1.size());
        serializedM1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("M1 sent\n");
    #endif




};

