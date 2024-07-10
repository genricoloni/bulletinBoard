#include "../utility/bbs.hpp"

BulletinBoardSystem::BulletinBoardSystem() {
    nextId = 0;
}

BulletinBoardSystem::~BulletinBoardSystem() {
}

void BulletinBoardSystem::Add(const std::string& title, const std::string& author, const std::string& body) {
    /*message m;
    m.id = nextId;
    m.title = title;
    m.author = author;
    m.body = body;
    messages.push_back(m);
    nextId++;*/
}

std::vector<message> BulletinBoardSystem::List(const int n) { 
    /*for (int i = 0; i < n && i < messages.size(); i++) {
        print("Author: " + messages[i].author + "\nTitle: " + messages[i].title + "\nBody: " + messages[i].body + "\n");
    }
    return;*/
}

message BulletinBoardSystem::Get(const int mid) {
    /*for (int i = 0; i < messages.size(); i++) {
        if (messages[i].id == mid) {
            print("Author: " + messages[i].author + "\nTitle: " + messages[i].title + "\nBody: " + messages[i].body + "\n");
            return;
        }
    }*/
}