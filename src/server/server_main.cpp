#include <iostream>
#include "../server/server.hpp"

int main(int argc, char const *argv[]){
    printf("Starting server\n");

    Server server(8080, 5); 
    printf("Server started\n");

    server.startListening();

    //wait for user input
    string command;
    while (true) {
        cout << "Enter a command: ";
        cin >> command;

        if (command == "stop") {
            break;
        }
    }
    return 0;
}