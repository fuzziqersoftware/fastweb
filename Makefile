OBJECTS=MIMEType.o ResourceManager.o Main.o
CXX=g++
CXXFLAGS=-I/opt/homebrew/opt/zlib/include -I/usr/local/opt/openssl@1.1/include -I/opt/local/include -std=c++14 -g -Wall -Werror
LDFLAGS=-L/opt/homebrew/opt/zlib/lib -L/opt/homebrew/opt/openssl@1.1/lib -L/opt/homebrew/lib -L/usr/local/opt/openssl@1.1/lib -L/opt/local/lib -std=c++14
LDLIBRARIES=-levent -levent_openssl -lssl -lcrypto -lphosg -lz -lpthread
EXECUTABLE=fastweb

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(LDLIBRARIES) -o $(EXECUTABLE)

clean:
	rm -rf *.dSYM *.o $(EXECUTABLE) $(EXECUTABLE)

.PHONY: clean
