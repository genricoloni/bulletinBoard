#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <atomic>
#include <mutex>
#include <condition_variable>


#include "../crypto/secureProtocol.hpp"
#include "../crypto/diffieHellman.hpp"
#include "../crypto/RSASignature.hpp"
#include "../crypto/AESCBC.hpp"
#include "../const.hpp"
#include "../crypto/sessionMessage.hpp"
#include "../utility/FileRWLock.hpp"
#include "../utility/bbs.hpp"
#include "../utility/TOPTGenerator.hpp"

/*
    * Job struct
    *
    * This struct is responsible for holding the client requests.
    * Each job is responsible for holding a single client request; once the client request is done, the job is free to hold another client request.

*/
struct job{
    std::vector<int> queue;
    std::atomic_bool isDone;
    std::mutex mutex;
    std::condition_variable cv;

};
typedef struct job job_t;

/*
    * Worker class
    *
    * This class is responsible for handling the client requests.
    * Each worker is responsible for handling a single client; once the client is done, the worker is free to handle another client.
*/

class Worker {
public:
    Worker(job_t* job, FileRWLock* fileLock, BulletinBoardSystem* bbs, FileRWLock* messageLock);
    ~Worker();

    void workerMain();

private:

    //shared structs
    FileRWLock* fileLock;
    FileRWLock* messageLock;
    BulletinBoardSystem* bbs;

    //variables for secure protocol
    job_t* job;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> hmacKey;
    std::vector<uint8_t> sessionKey;
    uint32_t counter;
    const std::string serverPrivateKeyPath = "res/keys/private/server.pem";

    //variables for user
    int userSocket;
    struct sockaddr_in userAddress;
    socklen_t userAddressLength;

    //thread logic functions
    void initiateProtocol();
    void waitForRequest();
    void AddHandler();
    void ListHandler();
    void GetHandler();

    //utility functions
    void sendAck();
    void sendError();
    ssize_t workerSend(const std::vector<uint8_t>& buffer);
    ssize_t receiveMessage(std::vector<uint8_t>& buffer, ssize_t bufferSize);


    //functions to handle login and register
    bool login();
    bool registerUser();

    bool checkUsername(const std::string& username);
    bool checkEmail(const std::string& email);
    void checkCounter(uint32_t counter);
    bool writeUser(const std::string& username, const std::string& email, const uint8_t* hashedPassword);
    bool checkPassword(const std::string& username, const uint8_t* hashedPassword);

};