#include "../client/client.hpp"
#include <limits>
#include <string.h>

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <server port>\n", argv[0]);
        exit(1);
    }

    if (atoi(argv[1]) < MIN_PORT || atoi(argv[1]) > MAX_PORT) {
        printf("Invalid port number. Port number must be between 1024 and 65535\n");
        exit(1);
    }

    Client client(atoi(argv[1]));

    printf("Client started\n");

    try {
        client.connectToServer();

        //insert the handshake phase to ensure secure connection here

    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    //wait for user input
    char* command = new char[256];
    bool logged = false;
    do {
        
        //clear the screen
        system("/bin/clear");
        std::cout << "Connected to server. Enter a command:\n";

        std::cout << "\t 0. exit\n";
        std::cout << "\t 1. login\n";
        std::cout << "\t 2. register\n";

        //read the command
        std::cin.getline(command, 256);

        //check how many characters the command has
        if (strlen(command) != 1){
            std::cout << "Insert a single number. Press any key to continue" << std::endl;
            getchar();
            continue;
        }

        //check if the command is a number
        if (!isdigit(command[0])){
            std::cout << "Insert a number. Press any key to continue" << std::endl;
            getchar();
            continue;
        }

        int cmd = BASE_CODE + atoi(command);
        
        switch (cmd){

        case EXIT_CODE:
            printf("Exiting\n");
            //exit from the program
            exit(0);

        case LOGIN_CODE:
            //login
            printf("Login\n");
            logged = client.initiateProtocol(uint32_t(LOGIN_CODE));
            break;

        case REGISTER_CODE:
            //register
            printf("Register\n");
            logged = client.initiateProtocol(uint32_t(REGISTER_CODE));
            
            break;

        default:
            std::cout << "Invalid command. Press any key to continue" << std::endl;
            getchar();

            //clean the output buffer

            break;
        }

        if (logged) {
            break;
        }

        //clean the command buffer
        std::memset(command, 0, 256);
    }
    while (true);

    do {
        //clear the screen
        system("/bin/clear");
        std::cout << "Welcome " << client.getUsername() << "! Enter a command:\n";

        std::cout << "\t 0. exit\n";
        std::cout << "\t 1. list\n";
        std::cout << "\t 2. get\n";
        std::cout << "\t 3. add\n";

        //read the command
        std::cin.getline(command, 256);

        //check how many characters the command has
        if (strlen(command) != 1){
            std::cout << "Insert a single number. Press any key to continue" << std::endl;
            getchar();
            continue;
        }

        //check if the command is a number
        if (!isdigit(command[0])){
            std::cout << "Insert a number. Press any key to continue" << std::endl;
            getchar();
            continue;
        }

        int cmd = BASE_CODE + atoi(command);
        
        switch (cmd){

        case EXIT_CODE:
            printf("Exiting\n");
            //exit from the program
            exit(0);

        case LIST_CODE:
            //list
            printf("Enter the number of messages to list\n");
            int n;
            std::cin >> n;

            client.list(n);
            break;

        case GET_CODE:
            //get
            printf("Get\n");
            int mID;
            std::cout << "Enter the message ID to get\n";
            std::cin >> mID;

            //sanitize the input
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            #ifdef DEBUG
            printf("DEBUG>> Inserted message ID: %d\n", mID);
            #endif
            client.get(mID);
            getchar();
  
            break;

        case ADD_CODE:
            //add
            printf("Add\n");
            client.add();
            getchar();

            break;

        default:
            std::cout << "Invalid command. Press any key to continue" << std::endl;
            getchar();

        getchar();
        //clean the command buffer
        std::memset(command, 0, 256);

            break;
        }

    } while (true);

    printf("Client finished\n");
    

    return 0;
    
    
}
