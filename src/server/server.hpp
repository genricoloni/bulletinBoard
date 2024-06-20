#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 

#include "../const.hpp"

using namespace std;

class Server {
public:
    Server(int port, int workerCount);
    ~Server();


    void acceptClient();

    void startListening();




private:
    int socket;

    int port;
    int workerCount;
    
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    int clientAddressLength;
    int clientSocket;

    void handleClient();
    void stopListening();



    sockaddr_in address(); //server address
};