#include "../client/client.hpp"
#include <cstring>




Client::Client(int port) : port(port){
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }


    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP);
    counter = 0;

    hmacKey.resize(SESSION_KEY_LENGTH);
    sessionKey.resize(SESSION_KEY_LENGTH);

}

Client::~Client() {
    ::close(socket);

    //clean the username
    username = "";
}

void Client::connectToServer() {

    printf("Connecting to server\n");

    if (connect(socket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        
        //call the destructor
        this->~Client();

        exit(1);
    }
    else {
        printf("Connected to server\n");
    }
}

void Client::sendToServer(const std::vector<uint8_t>& message) {
    ssize_t byteSent = 0;
    ssize_t totalByteSent = 0;
    ssize_t messageLength = message.size();

    while (totalByteSent < messageLength) {
        byteSent = send(socket, message.data() + totalByteSent, messageLength - totalByteSent, 0);
        if (byteSent == -1) {
            std::cerr << "Error sending message to server" << std::endl;
            return;
        }
        totalByteSent += byteSent;
    }
}

void Client::receiveFromServer(std::vector<uint8_t>& message) {
    ssize_t byteReceived = 0;
    ssize_t totalByteReceived = 0;
    ssize_t messageLength = message.size();

    while (totalByteReceived < messageLength) {
        byteReceived = recv(socket, message.data() + totalByteReceived, messageLength - totalByteReceived, 0);
        
        if(byteReceived != -1 && byteReceived != 0)
            totalByteReceived += byteReceived;
        

        if(byteReceived == 0)
            throw std::runtime_error("Connection closed by server");
        }
        
        if (byteReceived == -1) {
            throw std::runtime_error("Error receiving message from server");
        }
    }


bool Client::initiateProtocol(uint32_t mode) {
    #ifdef DEBUG
    printf("DEBUG>> Initiating communication to create secure connection\n");
    #endif

    //create the DiffieHellman object
    DiffieHellman dh;
    EVP_PKEY *EPH_KEY = nullptr;

    try {
        EPH_KEY = dh.generateEPHKey();
    }
    catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (EPH_KEY != nullptr) {
            EVP_PKEY_free(EPH_KEY);
        }
        throw std::runtime_error("Error generating EPH key");
    }

    //serialize EPHEMERAL KEY

    #ifdef DEBUG
    printf("DEBUG>> EPH key generated\n");
    #endif



    std::vector<uint8_t> serializedEPHKey;

    try{
        serializedEPHKey = DiffieHellman::serializeKey(EPH_KEY);
    }
    catch(const std::exception &e){
        EVP_PKEY_free(EPH_KEY);
        
        if (!serializedEPHKey.empty()) {
            std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
            serializedEPHKey.clear();
        }
        throw std::runtime_error("Error serializing EPH key");
    }

    #ifdef DEBUG
    printf("DEBUG>> EPH key serialized\n");
    #endif

    ProtocolM1 m1(serializedEPHKey, serializedEPHKey.size());

    std::vector<uint8_t> serializedM1;
    m1.serialize(serializedM1);

    try{
        sendToServer(serializedM1);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(serializedM1.data(), 0, serializedM1.size());
        serializedM1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> M1 sent\n");
    #endif

    std::vector<uint8_t> serializedM2(ProtocolM2::GetSize());

    try {
        receiveFromServer(serializedM2);
    } catch(const std::exception &e) {
        #ifdef DEBUG
            std::cerr << e.what() << std::endl;
        #endif

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(serializedM1.data(), 0, serializedM1.size());
        serializedM1.clear();

        std::memset(serializedM2.data(), 0, serializedM2.size());
        serializedM2.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM2 m2 = ProtocolM2::deserialize(serializedM2);
    serializedM2.clear();

    EVP_PKEY *serverEPHKey = nullptr;
    std::vector<uint8_t> sharedSecret;

    try {
        serverEPHKey = DiffieHellman::deserializeKey(m2.EPHKey.data(), m2.EPHKeyLength);

        dh.generateSharedSecret(EPH_KEY, serverEPHKey, sharedSecret, sharedSecret.size());
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (serverEPHKey != nullptr) {
            EVP_PKEY_free(serverEPHKey);
        }

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        EVP_PKEY_free(EPH_KEY);

        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        if(serverEPHKey != nullptr) 
            EVP_PKEY_free(serverEPHKey);
        
        throw std::runtime_error("Error generating shared secret");
    }

    #ifdef DEBUG
    //print ifno about sharedSecret
    printf("Shared secret buffer size: %ld\n", sharedSecret.size());
    printf("Shared secret buffer address: %p\n", reinterpret_cast<const unsigned char*>(sharedSecret.data()));
    #endif

    EVP_PKEY_free(serverEPHKey);
    EVP_PKEY_free(EPH_KEY);

    //generate hmac key from shared secret
    std::vector<uint8_t> keys;
    uint32_t keySize;

    try {
        SHA512::generateHash(sharedSecret.data(), sharedSecret.size(), keys, keySize);
        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
        serializedEPHKey.clear();

        std::memset(keys.data(), 0, keys.size());
        keys.clear();

        std::memset(sharedSecret.data(), 0, sharedSecret.size());
        sharedSecret.clear();

        throw std::runtime_error("Error generating HMAC key");
    }

    #ifdef DEBUG
    printf("DEBUG>> HMAC key generated\n");
    #endif

    std::memcpy(this->sessionKey.data(), keys.data(), (keys.size() / 2) * sizeof(uint8_t));
    std::memcpy(this->hmacKey.data(), keys.data() + (keys.size() / 2)* sizeof(uint8_t), HMAC_DIGEST_SIZE * sizeof(uint8_t));

    std::memset(keys.data(), 0, keys.size());
    keys.clear();

    #ifdef DEBUG
    printf("DEBUG>> Session key and HMAC key generated\n");
    #endif

    //prepare <g^a, g^b> for the server
    int EPHKeyBufferLength = m2.EPHKeyLength + serializedEPHKey.size();
    std::vector<uint8_t> EPHKeyBuffer(EPHKeyBufferLength);
    std::memcpy(EPHKeyBuffer.data(), serializedEPHKey.data(), serializedEPHKey.size());
    std::memcpy(EPHKeyBuffer.data() + serializedEPHKey.size(), m2.EPHKey.data(), m2.EPHKeyLength);

    std::memset(serializedEPHKey.data(), 0, serializedEPHKey.size());
    serializedEPHKey.clear();

    std::vector<uint8_t> signature;

    try {
        char privateKeyPath[] = "res/keys/private/client1.pem";

        RSASignature rsa(privateKeyPath, "");

        signature = rsa.sign(EPHKeyBuffer);

        #ifdef DEBUG
        printf("Signature generated\n");
        #endif
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        throw std::runtime_error("Error generating signature");
    }

    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> encryptedSignature;
    AESCBC* encryptor = nullptr;

    try {
        encryptor = new AESCBC(ENCRYPT, this->sessionKey);
        encryptor->run(signature, encryptedSignature, iv);
        delete encryptor;

        std::memset(signature.data(), 0, signature.size());
        signature.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (encryptor != nullptr) {
            delete encryptor;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        throw std::runtime_error("Error encrypting signature");
    }

    #ifdef DEBUG
    printf("DEBUG>> Signature encrypted\n");
    #endif

    std::vector<uint8_t> decryptedSignature;
    AESCBC* decryptor = nullptr;

    try {
        decryptor = new AESCBC(DECRYPT, this->sessionKey);
        decryptor->run(m2.encryptedSignature, decryptedSignature, m2.IV);
        delete decryptor;
        decryptedSignature.resize(DECRYPTED_SIGNATURE_SIZE);
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (decryptor != nullptr) {
            delete decryptor;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();

        throw std::runtime_error("Error decrypting signature");
    }

    //verify the signature
    RSASignature* rsa = nullptr;
    bool verified = true;

    try {
        //retrieve the public key of the server
        char publicKeyPath[] = "res/keys/public/server.pem";

        rsa = new RSASignature("", publicKeyPath);
        verified = rsa->verify(EPHKeyBuffer, decryptedSignature);
        delete rsa;

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        if (rsa != nullptr) {
            delete rsa;
        }

        std::memset(EPHKeyBuffer.data(), 0, EPHKeyBuffer.size());
        EPHKeyBuffer.clear();

        std::memset(signature.data(), 0, signature.size());
        signature.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();

        std::memset(decryptedSignature.data(), 0, decryptedSignature.size());
        decryptedSignature.clear();

        throw std::runtime_error("Error verifying signature");
    }

    if (!verified) {
        throw std::runtime_error("Signature not verified");
    } else {
        #ifdef DEBUG
        printf("Signature verified\n");
        #endif
    }


    ProtocolM3 m3(iv, encryptedSignature, mode);

    std::vector<uint8_t> serializedM3 = m3.serialize();

    try{
        sendToServer(serializedM3);

        std::memset(iv.data(), 0, iv.size());
        iv.clear();

        std::memset(encryptedSignature.data(), 0, encryptedSignature.size());
        encryptedSignature.clear();
    } catch (const std::exception &e) {
        #ifdef DEBUG
        std::cerr << e.what() << std::endl;
        #endif

        std::memset(serializedM3.data(), 0, serializedM3.size());
        serializedM3.clear();

        throw std::runtime_error("Error serializing M3");
    }
    
    #ifdef DEBUG
    printf("DEBUG>> M3 sent\n");
    #endif

    if(mode == LOGIN_CODE){
        //call the login function
        login();
    } else if(mode == REGISTER_CODE){
        //call the register function
        if (!registerUser()) {
            std::cerr << "Registration failed" << std::endl;
            return false;
        }

        //call the login function
        if (!login()) {
            std::cerr << "Login failed" << std::endl;
            return false;
        }
        
    } else {
        std::cerr << "Invalid mode" << std::endl;
        return false;
    }

    return true;
    
};

bool Client::login(){
    #ifdef DEBUG
    printf("DEBUG>> Login function\n");
    #endif
    printf("LOGIN\n");

    bool success = false;


    std::string username;
    std::string password;

    //get the username
    printf("Insert username: ");
    std::cin >> username;
    getchar();

    //copy the username to the class variable
    memset(this->username.data(), 0, this->username.size());
    this->username = std::string(username);

    //get the password
    char ch;
    printf("Insert password: ");
    //turnOffEcho();
    do {
        ch = getchar();
        if (ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch == '\n' || ch == '\r') {
            break;
        } else {
            password += ch;
            std::cout << "*";
        }  
    } while (ch != '\n' && ch != '\r' && password.size() < PASSWORD_MAX_SIZE);

    //turnOnEcho();

    #ifdef DEBUG
    printf("DEBUG>> Password inserted: %s\n", password.c_str());
    #endif

    //prepare the message with the username and empty email
    ProtocolM4Reg_Usr m4(username, "");

    std::vector<uint8_t> serializedM4;
    serializedM4 = m4.serialize();

    try {
        sendToServer(serializedM4);
        #ifdef DEBUG
        printf("M4 sent\n");
        #endif
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedM4.data(), 0, serializedM4.size());
        serializedM4.clear();

        throw std::runtime_error("Error sending message to server");
    }

    //receive the message from the server
    std::vector<uint8_t> serializedM4Response(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(serializedM4Response);

    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedM4Response.data(), 0, serializedM4Response.size());
        serializedM4Response.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response = ProtocolM4Response::deserialize(serializedM4Response);
    std::memset(serializedM4Response.data(), 0, serializedM4Response.size());
    serializedM4Response.clear();

    if (m4Response.response == USR_NOT_FOUND) {
        std::cerr << "Username not found" << std::endl;
        return success;
    }

    //send the password
    sendPassword(password);

    //receive the message from the server
    std::vector<uint8_t> serializedM4Response1(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(serializedM4Response1);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedM4Response1.data(), 0, serializedM4Response1.size());
        serializedM4Response1.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response1 = ProtocolM4Response::deserialize(serializedM4Response1);
    std::memset(serializedM4Response1.data(), 0, serializedM4Response1.size());

    if (m4Response1.response == WRONG_PASSWORD) {
        std::cerr << "Wrong password" << std::endl;
        return success;
    }

    if (m4Response1.response == ACK) {
        success = true;
        printf("Login successful: welcome %s\n", username.c_str());
        return success;
    } else {
        std::cerr << "Login failed" << std::endl;
        return success;
    }
    
}

// Include the necessary header file
#include <termios.h>

// Function to turn off console echo
void Client::turnOffEcho() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to turn on console echo
void Client::turnOnEcho() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    std::cout << std::endl;
}



bool Client::registerUser(){
    #ifdef DEBUG
    printf("DEBUG>> Register function\n");
    #endif

    bool success = false;

    std::string username;
    std::string password;
    std::string mail;

    //get the username
    printf("Insert username: ");
    std::cin >> username;
    getchar();

    //copy the username to the class variable
    memset(this->username.data(), 0, this->username.size());
    this->username = std::string(username);

    //get the mail
    printf("Insert mail: ");
    std::cin >> mail;
    getchar();

    #ifdef DEBUG
    printf("DEBUG>> Username and mail inserted\n"); 
    printf("Username: %s\n", username.c_str());
    printf("Mail: %s\n", mail.c_str());
    #endif

    //prepare the message
    ProtocolM4Reg_Usr m4(username, mail);

    std::vector<uint8_t> serializedM4;
    serializedM4 = m4.serialize();

    try {
        sendToServer(serializedM4);
        #ifdef DEBUG
        printf("M4 sent\n");
        #endif
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedM4.data(), 0, serializedM4.size());
        serializedM4.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    //try to deserialize the message m4 and print the content
    ProtocolM4Reg_Usr m4_1 = ProtocolM4Reg_Usr::deserialize(serializedM4);
    printf("M4 deserialized\n");
    printf("Username: %s\n", m4_1.username.c_str());
    printf("Mail: %s\n", m4_1.email.c_str());
    #endif

    //receive the message from the server
    std::vector<uint8_t> serializedM4Response(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(serializedM4Response);
        #ifdef DEBUG
        printf("M4 response received\n");
        #endif
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedM4Response.data(), 0, serializedM4Response.size());
        serializedM4Response.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response = ProtocolM4Response::deserialize(serializedM4Response);
    std::memset(serializedM4Response.data(), 0, serializedM4Response.size());

    if (m4Response.response == USR_ALREADY_TAKEN) {
        std::cerr << "Username already taken" << std::endl;
        return success;
    }

    if (m4Response.response == MAIL_ALREADY_TAKEN) {
        std::cerr << "Mail already taken" << std::endl;
        return success;
    }

    //get the password
    char ch;
    printf("Insert password: ");
    turnOffEcho();
    do {
        ch = getchar();
        if (ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch == '\n' || ch == '\r') {
            break;
        } else {
            password += ch;
            std::cout << "*";
        }  
    } while (ch != '\n' && ch != '\r' && password.size() < PASSWORD_MAX_SIZE);
    turnOnEcho();

    #ifdef DEBUG
    printf("DEBUG>> Password inserted: %s\n", password.c_str());
    #endif

    sendPassword(password);

    #ifdef DEBUG
    printf("DEBUG>> Password sent\n");
    #endif

    //sent a message to the server with the OTP
    std::string otp;
    printf("Insert OTP: ");
    std::cin >> otp;
    getchar();

    //using a normal session message
    std::vector<uint8_t> serializedOTP(otp.size());
    std::memcpy(serializedOTP.data(), otp.c_str(), otp.size());

    sessionMessage sessionMessage(this->sessionKey, this->hmacKey, serializedOTP);

    std::vector<uint8_t> serializedSessionMessage = sessionMessage.serialize();

    try {
        sendToServer(serializedSessionMessage);
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> OTP sent\n");
    #endif

    //receive the response from the server
    std::vector<uint8_t> m4ResponseBuffer(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(m4ResponseBuffer);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
        m4ResponseBuffer.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response1 = ProtocolM4Response::deserialize(m4ResponseBuffer);

    std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
    m4ResponseBuffer.clear();

    if (m4Response1.response == ACK) {
        success = true;
        #ifdef DEBUG
        printf("Registration successful\n");
        #endif
    } else {
        std::cerr << "Registration failed" << std::endl;
    }

    return success;
}

void Client::sendPassword(std::string password) {
    //MODIFY TO SEND HASHED PASSWORD
    IncrementCounter();

    PasswordMessage message(password.c_str(), this->counter);

    std::vector<uint8_t> plaintext(PWD_MESSAGE1_SIZE);
    message.serialize(plaintext);

    #ifdef DEBUG
    printf("DEBUG>> Password message serialized\n");
    #endif

    sessionMessage sessionMessage(this->sessionKey, this->hmacKey, plaintext);

    #ifdef DEBUG
    printf("DEBUG>> created session message\n");
    #endif

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();

    #ifdef DEBUG
    printf("DEBUG>> Serializing session message\n");
    #endif

    std::vector<uint8_t> serializedSessionMessage = sessionMessage.serialize();

    #ifdef DEBUG
    printf("DEBUG>> Password message serialized\n");
    #endif

    try {
        sendToServer(serializedSessionMessage);
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Password message sent\n");
    #endif

    return;

}

void Client::IncrementCounter() {
    if (this->counter + 1 == 0)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");

    this->counter++;
}
 

void Client::list(int n){
    //prepare the message with the code 
    //using a normal session message
    std::vector<uint8_t> serializedCode(sizeof(LIST_CODE));
    uint32_t code = htonl(LIST_CODE);

    std::memcpy(serializedCode.data(), &code, sizeof(code));

    sessionMessage s1(this->sessionKey, this->hmacKey, serializedCode);    

    #ifdef DEBUG
    printf("DEBUG>> Size of the unserialized message: %d\n", sizeof(s1));
    #endif

    std::vector<uint8_t> serializedSessionMessage = s1.serialize();

    
    #ifdef DEBUG
    printf("DEBUG>> Size of serialized message: %d\n", sizeof(serializedSessionMessage));
    #endif

    try {
        sendToServer(serializedSessionMessage);
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Code sent\n");
    #endif

    //receive the response from the server
    std::vector<uint8_t> m4ResponseBuffer(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(m4ResponseBuffer);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
        m4ResponseBuffer.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response1 = ProtocolM4Response::deserialize(m4ResponseBuffer);

    std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
    m4ResponseBuffer.clear();

    if (m4Response1.response == ACK) {
        #ifdef DEBUG
        printf("List successful\n");
        #endif
    } else {
        std::cerr << "List failed" << std::endl;
    }
    

    //send the number of messages to list
    std::vector<uint8_t> serializedN(sizeof(n));
    uint32_t n1 = htonl(n);

    std::memcpy(serializedN.data(), &n1, sizeof(n1));

    sessionMessage s2(this->sessionKey, this->hmacKey, serializedN);

    std::vector<uint8_t> serializedSessionMessage1 = s2.serialize();

    try {
        sendToServer(serializedSessionMessage1);
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Number of messages sent\n");
    #endif

    //compute the size of the message
    int messageSize = MAX_MESSAGE_SIZE * n + s1.iv.size() + s1.hmac.size();

    std::vector<uint8_t> message(messageSize);

    try {
        receiveFromServer(message);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(message.data(), 0, message.size());
        message.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    //decrypt the message
    std::vector<uint8_t> plaintext(MAX_MESSAGE_SIZE * n);
    sessionMessage s3 = sessionMessage::deserialize(message, MAX_MESSAGE_SIZE * n);

    std::memset(message.data(), 0, message.size());
    message.clear();

    uint16_t plaintextSize = s3.decrypt(this->sessionKey, plaintext);

    if (plaintextSize == 0) {
        std::cerr << "Error decrypting message" << std::endl;
        std::memset(plaintext.data(), 0, plaintext.size());
        plaintext.clear();

        throw std::runtime_error("Error decrypting message");
    }

    //instance of a vector of message struct
    std::vector<struct message> messages;

    //parse the plaintext
    int i = 0;

    while (i < plaintextSize) {
        struct message m;
        m.id = ntohl(*reinterpret_cast<uint32_t*>(plaintext.data() + i));
        i += sizeof(uint32_t);

        m.author = std::string(reinterpret_cast<char*>(plaintext.data() + i));
        i += m.author.size() + 1;

        m.title = std::string(reinterpret_cast<char*>(plaintext.data() + i));
        i += m.title.size() + 1;

        m.body = std::string(reinterpret_cast<char*>(plaintext.data() + i));
        i += m.body.size() + 1;

        messages.push_back(m);
    }

    //print the messages
    for (int i = 0; i < messages.size(); i++) {
        printf("ID: %d\n", messages[i].id);
        printf("Author: %s\n", messages[i].author.c_str());
        printf("Title: %s\n", messages[i].title.c_str());
        printf("Body: %s\n", messages[i].body.c_str());
        printf("\n");
    }

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();

    return;   
}

void Client::add(){
    std::vector<uint8_t> serializedCode(sizeof(ADD_CODE));
    uint32_t code = htonl(ADD_CODE);

    std::memcpy(serializedCode.data(), &code, sizeof(code));

    sessionMessage s1(this->sessionKey, this->hmacKey, serializedCode);    

    #ifdef DEBUG
    printf("DEBUG>> Size of the unserialized message: %d\n", sizeof(s1));
    #endif

    std::vector<uint8_t> serializedSessionMessage = s1.serialize();


    try {
        sendToServer(serializedSessionMessage);
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Code sent\n");
    #endif

    //receive the response from the server
    std::vector<uint8_t> m4ResponseBuffer(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(m4ResponseBuffer);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
        m4ResponseBuffer.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    ProtocolM4Response m4Response1 = ProtocolM4Response::deserialize(m4ResponseBuffer);

    std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());

    if (m4Response1.response == ACK) {
        #ifdef DEBUG
        printf("Add successful\n");
        #endif
    } else {
        std::cerr << "Add failed" << std::endl;
    }

    struct message m;

    //get the author
    m.author = this->username;
    
    std::string title(MAX_TITLE_SIZE, '\0');
    std::string body(MAX_BODY_SIZE, '\0');

    //get the title
    printf("Insert title: ");
    std::cin >> title;
    getchar();

    //get the body
    printf("Insert body: ");
    std::cin >> body;
    getchar();

    m.title = title;
    m.body = body;

    //padding to reach the maximum size
    if (m.title.size() < MAX_TITLE_SIZE) {
        m.title.resize(MAX_TITLE_SIZE, '\0');
    }

    if (m.body.size() < MAX_BODY_SIZE) {
        m.body.resize(MAX_BODY_SIZE, '\0');
    }

    if (m.author.size() < NAME_SIZE) {
        m.author.resize(NAME_SIZE, '\0');
    }

    //serialize the message
    std::vector<uint8_t> serializedMessage(MAX_MESSAGE_SIZE);
    int i = 0;
    
    #ifdef DEBUG
    m.id = 22;
    #endif

    std::memcpy(serializedMessage.data() + i, &m.id, sizeof(uint32_t));
    i += sizeof(uint32_t);

    std::memcpy(serializedMessage.data() + i, m.author.c_str(), m.author.size());
    i += NAME_SIZE;

    std::memcpy(serializedMessage.data() + i, m.title.c_str(), m.title.size());
    i += MAX_TITLE_SIZE;

    std::memcpy(serializedMessage.data() + i, m.body.c_str(), m.body.size());
    i += MAX_BODY_SIZE;

    sessionMessage s2(this->sessionKey, this->hmacKey, serializedMessage);

    #ifdef DEBUG
    printf("DEBUG>> ID: %d\n", serializedMessage[0]);
    printf("DEBUG>> Author: %s\n", reinterpret_cast<char*>(serializedMessage.data() + sizeof(uint32_t)));
    printf("DEBUG>> Title: %s\n", reinterpret_cast<char*>(serializedMessage.data() + sizeof(uint32_t) + NAME_SIZE));
    printf("DEBUG>> Body: %s\n", reinterpret_cast<char*>(serializedMessage.data() + sizeof(uint32_t) + NAME_SIZE + MAX_TITLE_SIZE));
    #endif

    //encrypt the message
    std::vector<uint8_t> ciphertext(MAX_MESSAGE_SIZE);
    

    std::vector<uint8_t> serializedSessionMessage1 = s2.serialize();



    try {
        sendToServer(serializedSessionMessage1);
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Message sent\n");
    #endif

    return;    
}

void Client::get(int requestedID){
    
    //prepare the message with the code
    std::vector<uint8_t> serializedCode(sizeof(GET_CODE));
    uint32_t code = htonl(GET_CODE);

    std::memcpy(serializedCode.data(), &code, sizeof(code));

    sessionMessage s1(this->sessionKey, this->hmacKey, serializedCode);

    std::vector<uint8_t> serializedSessionMessage = s1.serialize();

    try {
        sendToServer(serializedSessionMessage);
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage.data(), 0, serializedSessionMessage.size());
        serializedSessionMessage.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Code sent\n");
    #endif

    //receive the response from the server
    std::vector<uint8_t> m4ResponseBuffer(ProtocolM4Response::GetSize());

    try {
        receiveFromServer(m4ResponseBuffer);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());
        m4ResponseBuffer.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Response received\n");
    #endif

    ProtocolM4Response m4Response1 = ProtocolM4Response::deserialize(m4ResponseBuffer);

    std::memset(m4ResponseBuffer.data(), 0, m4ResponseBuffer.size());

    if (m4Response1.response == ACK) {
        #ifdef DEBUG
        printf("Get successful\n");
        #endif
    } else {
        std::cerr << "Get failed" << std::endl;
    }

    #ifdef DEBUG
    printf("DEBUG>> ACK received\n");
    #endif

    //send the requested ID
    std::vector<uint8_t> serializedID(sizeof(requestedID));
    uint32_t id = htonl(requestedID);

    std::memcpy(serializedID.data(), &id, sizeof(id));

    sessionMessage s2(this->sessionKey, this->hmacKey, serializedID);

    std::vector<uint8_t> serializedSessionMessage1 = s2.serialize();

    try {
        sendToServer(serializedSessionMessage1);
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(serializedSessionMessage1.data(), 0, serializedSessionMessage1.size());
        serializedSessionMessage1.clear();

        throw std::runtime_error("Error sending message to server");
    }

    #ifdef DEBUG
    printf("DEBUG>> ID sent\n");
    #endif

    //compute the size of the message

    std::vector<uint8_t> message(sessionMessage::get_size(MAX_MESSAGE_SIZE));

    try {
        receiveFromServer(message);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::memset(message.data(), 0, message.size());
        message.clear();

        throw std::runtime_error("Error receiving message from server");
    }

    #ifdef DEBUG
    printf("DEBUG>> Message received\n");
    #endif
    

    sessionMessage s3 = sessionMessage::deserialize(message, MAX_MESSAGE_SIZE);

    std::vector<uint8_t> plaintext(sessionMessage::get_size(MAX_MESSAGE_SIZE));
    s3.decrypt(this->sessionKey, plaintext);

    #ifdef DEBUG
    printf("DEBUG>> ID: %d\n", plaintext[0]);
    #endif

    if (plaintext[0] == 0) {
        std::cerr << "Message not found" << std::endl;
        std::memset(plaintext.data(), 0, plaintext.size());
        plaintext.clear();

        return;
    }

    void* address = &plaintext[0];

    #ifdef  DEBUG
    printf("DEBUG>> Address: %p\n", address);
    #endif

    std::string author(reinterpret_cast<char*>(address + sizeof(uint32_t)));

    #ifdef DEBUG
    printf("DEBUG>> Author: %s\n", author.c_str());
    #endif

    address = address + sizeof(uint32_t) + NAME_SIZE*sizeof(uint8_t);

    std::string title(reinterpret_cast<char*>(address));

    #ifdef DEBUG
    printf("DEBUG>> Title: %s\n", title.c_str());
    #endif

    address = address + MAX_TITLE_SIZE*sizeof(uint8_t);

    std::string body(reinterpret_cast<char*>(address));

    #ifdef DEBUG
    printf("DEBUG>> Body: %s\n", body.c_str());
    #endif

    std::memset(plaintext.data(), 0, plaintext.size());
    plaintext.clear();

    printf("RECEIVED MESSAGE\n");
    printf("\tAuthor: %s\n", author.c_str());
    printf("\tTitle: %s\n", title.c_str());
    printf("\tBody: %s\n", body.c_str());

    return;
    
    
}

   
