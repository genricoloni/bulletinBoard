#include <iostream>
#include "../server/server.hpp"
#include <csignal>

volatile sig_atomic_t signal_caught = 0;

void signal_handler(int signal){
    if (signal == SIGINT){
        signal_caught = 1;
        std::cout << "Caught signal: " << signal << '\n';

        exit(0);
    }
}


int main(int argc, char const *argv[]){
    printf("Starting server\n");

    int number_of_workers = argc > 1 ? std::stoi(argv[1]) : MIN_WORKERS;

    if (number_of_workers < MIN_WORKERS){
        std::cerr << "Invalid number of workers, setting to minimum\n";
        number_of_workers = MIN_WORKERS;
    }

    if (number_of_workers > MAX_WORKERS){
        std::cerr << "Invalid number of workers, setting to maximum\n";
        number_of_workers = MAX_WORKERS;
    }

    try {

        Server server(8080, number_of_workers, &signal_caught);
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