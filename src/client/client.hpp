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
#include "../utility/bbs.hpp"


class Client {
public:
    
    Client(int port);
    ~Client();

    //connection and communication
    void connectToServer();
    void sendToServer(const std::vector<uint8_t>& message);
    void receiveFromServer(std::vector<uint8_t>& message);

    bool initiateProtocol(uint32_t mode);

    //login-register
    bool login();
    bool registerUser();

    //client logic
    void list(int n);
    void get(int mID);
    void add();

    std::string getUsername(){
        return username;
    }

private:
    int socket;
    int port;

    struct sockaddr_in serverAddress;

    std::string username;

    //secure protocol variables
    uint32_t counter; 
    std::vector<uint8_t> hmacKey;
    std::vector<uint8_t> sessionKey;

    //utility functions
    void turnOnEcho();
    void turnOffEcho();
    void IncrementCounter();

    void sendPassword(std::string password);
};