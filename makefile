# Empty target to prevent implicit build
.PHONY: all

# Compiler
CC = g++

# Flags 
CFLAGS = -g -std=c++17 -Wno-deprecated-declarations  # -Wall for warnings, -g for debugging symbols, -std=c++17 for C++17 standard

# Output binary names 
BIN_CLIENT = client
BIN_SERVER = server

# Include directories for header files 
CPPINCLUDE = -I./src/client -I./src/server -I./src/crypto  # Include crypto directory

# Target to build the client executable
client: src/client/*.cpp src/crypto/*.cpp
	$(CC) $(CFLAGS) $(CPPINCLUDE) -o bin/$(BIN_CLIENT) src/client/*.cpp src/crypto/*.cpp -lcrypto

# Compile individual client source files into object files
%.o: src/client/%.cpp src/crypto/%.cpp
	$(CC) $(CFLAGS) $(CPPINCLUDE) -c $< -o $@  # Create object file

# Target to build the server executable
server: src/server/*.cpp src/crypto/*.cpp
	$(CC) $(CFLAGS) $(CPPINCLUDE) -o bin/$(BIN_SERVER) src/server/*.cpp src/crypto/*.cpp -lcrypto

# Compile individual server source files into object files
%.o: src/server/%.cpp src/crypto/%.cpp
	$(CC) $(CFLAGS) $(CPPINCLUDE) -c $< -o $@  # Create object file

# Build both client and server when "all" is targeted
all: client server

# Phony target for cleaning (remove built files)
.PHONY: clean

clean:
	rm -f bin/$(BIN_CLIENT) bin/$(BIN_SERVER) *.o  # Remove executables (from bin) and object files (if any)

# Usage message
usage:
	@echo "Usage:"
	@echo "  make client: Build the client executable"
	@echo "  make server: Build the server executable"
	@echo "  make all: Build both client and server executables"
	@echo "  make clean: Remove built files"
	@echo "  make usage: Display this message"

.DEFAULT_GOAL := usage
