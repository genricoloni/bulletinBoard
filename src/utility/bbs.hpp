#include <iostream>
#include <vector>
#include <string.h>
#include <sys/types.h>


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
    BulletinBoardSystem();
    ~BulletinBoardSystem();


private:
    std::vector<message> messages;
    int nextId;

    void Add(const std::string& title, const std::string& author, const std::string& body);
    std::vector<message> List(const int n);
    message Get(const int mid);
};