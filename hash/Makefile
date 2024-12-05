CC = g++
CFLAGS = -std=c++17 -Wall -I/usr/include/cryptopp
LDFLAGS = -lcryptopp

TARGET = hash
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
