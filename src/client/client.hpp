#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 

#include "../const.hpp"
#include "../crypto/diffieHellman.hpp"


class Client {
public:
    
    Client(int port);
    ~Client();

    void connectToServer();
    void sendToServer(const std::string& message);
    std::string receiveFromServer();

    void list(int n);
    void get(int mID);
    void add();

private:
    int socket;
    int port;

    struct sockaddr_in serverAddress;

    std::string username;


};