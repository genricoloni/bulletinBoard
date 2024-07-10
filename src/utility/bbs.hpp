#include <iostream>
#include <vector>
#include <string.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <algorithm>


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
    BulletinBoardSystem() : nextId(0) {};
    ~BulletinBoardSystem();

    void Add(const std::string& title, const std::string& author, const std::string& body){
        message m;
        m.id = nextId;
        m.title = title;
        m.author = author;
        m.body = body;
        messages.insert(messages.begin(),m);
        nextId++;
    }
    std::vector<message> List(const int n) {
        std::vector<message> lastNMessages;
        for (int i = 0; i < n && i < messages.size(); i++) {
            lastNMessages.push_back(messages[i]);
        }
        return lastNMessages;
    }
    message Get(const int mid) {
        for (int i = 0; i < messages.size(); i++) {
            if (messages[i].id == mid) {
                return messages[i];
            }
        }
        message m;
        m.id = -1;
        return m;
    }
    std::vector<uint8_t> serialize(const message msg) {
        ssize_t buffer_size = msg.author.size() + msg.body.size() + msg.title.size();
        std::vector<uint8_t> buffer(buffer_size);

        ssize_t position = 0;

        std::copy(msg.author.begin(), msg.author.end(), buffer.begin() + position);
        position += msg.author.size();

        std::copy(msg.body.begin(), msg.body.end(), buffer.begin() + position);
        position += msg.body.size();

        std::copy(msg.title.begin(), msg.title.end(), buffer.begin() + position);
        position += msg.title.size();

        return buffer;
    }
private:
    std::vector<message> messages;
    int nextId;
};