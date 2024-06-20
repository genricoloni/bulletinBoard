# Empty target to prevent implicit build
.PHONY: all

# Compiler (replace with your compiler if needed)
CC = g++

# Flags (adjust as necessary)
CFLAGS = -Wall -g -std=c++17  # -Wall for warnings, -g for debugging symbols, -std=c++17 for C++17 standard

# Output binary name
BIN = client

# Include directory for header files (adjust as needed)
CPPINCLUDE = -I./src/client

# Target to build the executable
client: src/client/*.cpp
	$(CC) $(CFLAGS) $(CPPINCLUDE) -o bin/$(BIN) src/client/*.cpp 


# Phony target for cleaning (remove built files)
.PHONY: clean

clean:
	rm -f bin/$(BIN) *.o  
usage:
	@echo "Usage: make [all|client|clean|usage]"

.DEFAULT_GOAL := usage