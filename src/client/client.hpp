#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 

#include "../const.hpp"

#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "../crypto/diffieHellman.hpp"
#include "../crypto/secureProtocol.hpp"
#include "../crypto/RSASignature.hpp"
#include "../crypto/sessionMessage.hpp"
#include "../crypto/AESCBC.hpp"


class Client {
public:
    
    Client(int port);
    ~Client();

    void connectToServer();
    void sendToServer(const std::vector<uint8_t>& message);
    void receiveFromServer(std::vector<uint8_t>& message);

    void initiateProtocol(uint32_t mode);

    bool login();
    bool registerUser();

    void list(int n);
    void get(int mID);
    void add();

private:
    int socket;
    int port;

    struct sockaddr_in serverAddress;

    std::string username;


    uint32_t counter; 
    std::vector<uint8_t> hmacKey;
    std::vector<uint8_t> sessionKey;

    void turnOnEcho();
    void turnOffEcho();

    void HashPassword(const std::string& password, std::vector<uint8_t>& hashedPassword);
    void sendPassword(std::string password);
    void IncrementCounter();


};