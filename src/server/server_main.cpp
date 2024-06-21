#include <iostream>
#include "../server/server.hpp"

int main(int argc, char const *argv[]){
    printf("Starting server\n");

    Server server(8080, 5); 
    printf("Server started\n");

    server.startListening();

    //wait for user input
    std::string command;
    std::cin >> command;
    while (true) {

        printf("Accepting client\n");
        server.acceptClient();
        std::cin >> command;


    }
    return 0;
}