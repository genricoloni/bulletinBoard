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
    uint32_t id;
    std::string author;
    std::string title;
    std::string body;

    message() {}

    message(uint32_t id, std::string author, std::string title, std::string body) : id(id), author(author), title(title), body(body) {}

    ~message() {}
};

//typedef of the message struct
typedef struct message message;

/* bulletin board class */
class BulletinBoardSystem {
public:
    BulletinBoardSystem() : nextId(1) {};
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
    std::vector<uint8_t> serialize(struct message msg) {
        //ssize_t buffer_size = sizeof(msg.id) + msg.author.size() + msg.body.size() + msg.title.size();
        std::vector<uint8_t> buffer(MAX_MESSAGE_SIZE);

        ssize_t position = 0;

        //padding to reach the maximum size
        if (msg.title.size() < MAX_TITLE_SIZE) {
            msg.title.resize(MAX_TITLE_SIZE, '\0');
        }

        if (msg.body.size() < MAX_BODY_SIZE) {
            msg.body.resize(MAX_BODY_SIZE, '\0');
        }

        if (msg.author.size() < NAME_SIZE) {
            msg.author.resize(NAME_SIZE, '\0');
        }

        // copy the msg.id at the beginning of the buffer
        #ifdef DEBUG
            printf("DEBUG>> ID: %d\n", &msg.id);
        #endif
        
        // copy the msg.id at the beginning of the buffer
        std::memcpy(buffer.data() + position, &msg.id, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(buffer.data() + position, msg.author.c_str(), msg.author.size());
        position += NAME_SIZE;

        std::memcpy(buffer.data() + position, msg.title.c_str(), msg.title.size());
        position += MAX_TITLE_SIZE;

        std::memcpy(buffer.data() + position, msg.body.c_str(), msg.body.size());
        position += MAX_BODY_SIZE;

        return buffer;
    }

    void printHead(){
        printf("DEBUG>> Bulletin Board System\n");
        printf("\tID>> %d", messages.front().id);
        printf("\tAuthor>> %s\n", messages.front().author.c_str());
        printf("\tTitle>> %s\n", messages.front().title.c_str());
        printf("\tBody>> %s\n", messages.front().body.c_str());
    }
private:
    std::vector<message> messages;
    int nextId;
};