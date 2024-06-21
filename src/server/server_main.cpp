#include <iostream>
#include "../server/server.hpp"
#include <csignal>

volatile sig_atomic_t signal_caught = 0;

void signal_handler(int signal){
    if (signal == SIGINT){
        signal_caught = 1;
        std::cout << "Caught signal: " << signal << '\n';
    }
}


int main(int argc, char const *argv[]){
    printf("Starting server\n");

    try {

        Server server(8080, 5, &signal_caught);
        printf("Server started\n");

        //wait for user input
        std::signal(SIGINT, signal_handler);

        server.startListening();

        server.acceptClient();

        }
    catch (std::invalid_argument& e){
        std::cerr << e.what() << '\n';
        return -1;

    }

    catch (std::runtime_error& e){
        std::cerr << e.what() << '\n';
        return -1;

    }

    catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return -1;

    }
    

    return 0;
}