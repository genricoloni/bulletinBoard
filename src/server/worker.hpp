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
#include "../crypto/TOPTGenerator.hpp"
#include "FileRWLock.hpp" 
#include "../utility/bbs.hpp"

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

    FileRWLock* fileLock;
    BulletinBoardSystem* bbs;

    FileRWLock* messageLock;

    job_t* job;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> hmacKey;
    std::vector<uint8_t> sessionKey;
    uint32_t counter;

    const std::string serverPrivateKeyPath = "res/keys/private/server.pem";

    ssize_t workerSend(const std::vector<uint8_t>& buffer);
    ssize_t workerReceive(std::vector<uint8_t>& buffer, ssize_t bufferSize);
    

    int userSocket;
    struct sockaddr_in userAddress;
    socklen_t userAddressLength;
    void handleUser();

    void initiateProtocol();

    ssize_t receiveMessage(std::vector<uint8_t>& buffer, ssize_t bufferSize);

    bool login();
    bool registerUser();

    bool checkUsername(const std::string& username);
    bool checkEmail(const std::string& email);
    void checkCounter(uint32_t counter);
    bool writeUser(const std::string& username, const std::string& email, const uint8_t* hashedPassword);
    bool checkPassword(const std::string& username, const uint8_t* hashedPassword);

    void waitForRequest();
    void AddHandler(const std::string& title, const std::string& author, const std::string& body);
    void ListHandler();
    void GetHandler(const int mid);
};