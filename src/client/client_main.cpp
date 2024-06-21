#include "../client/client.hpp"

int main() {

    printf("Starting client\n");

    printf("Server IP: %s\n", SERVER_IP);
    Client client;

    printf("Client started\n");

    //wait for user input
    std::string command;
    while (true) {
        std::cout << "Enter a command: ";
        std::cin >> command;

        if (command == "list") {
            printf("Listing\n");
        } 

    }

    return 0;
    
    
}