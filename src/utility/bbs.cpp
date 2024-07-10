#include "../utility/bbs.hpp"

BulletinBoardSystem::BulletinBoardSystem() {
    nextId = 0;
}

BulletinBoardSystem::~BulletinBoardSystem() {
}

void BulletinBoardSystem::Add(const std::string& title, const std::string& author, const std::string& body) {
    message m;
    m.id = nextId;
    m.title = title;
    m.author = author;
    m.body = body;
    messages.insert(messages.begin(),m);
    nextId++;
}

std::vector<message> BulletinBoardSystem::List(const int n) { 
    // obtain the last n messages
    std::vector<message> lastNMessages;
    for (int i = 0; i < n && i < messages.size(); i++) {
        lastNMessages.push_back(messages[i]);
    }
    return lastNMessages;
}

message BulletinBoardSystem::Get(const int mid) {
    // obtain the message with the given id
    for (int i = 0; i < messages.size(); i++) {
        if (messages[i].id == mid) {
            return messages[i];
        }
    }
    message m;
    m.id = -1;
    return m;
}