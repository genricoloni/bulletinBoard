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


/* message struct that represent the messages to write in the bulletin: id, author, title and body */
struct message {
    int id;
    std::string title;
    std::string author;
    std::string body;
};

/* bulletin board class */
class BulletinBoardSystem {
public:
    BulletinManager();
    ~BulletinManager();

private:
    std::vector<message> messages;
    int nextId;

    void Add(const std::string& title, const std::string& author, const std::string& body);
    std::vector<message> List(const int n);
    message Get(const int mid);
};