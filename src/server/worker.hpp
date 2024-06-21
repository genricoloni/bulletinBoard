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
    Worker(job_t* job);
    ~Worker();

    void workerMain();

private:

    job_t* job;


    int userSocket;
    struct sockaddr_in userAddress;
    socklen_t userAddressLength;
    void handleUser();
};