CXX = g++
CXXFLAGS = -std=c++11 -I/usr/include/cryptopp
LDFLAGS = -lcryptopp

SRC = main.cpp
OUT = main

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

clean:
	rm -f $(OUT)
