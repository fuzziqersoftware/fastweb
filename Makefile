OBJECTS=MIMEType.o ResourceManager.o Main.o
CXX=g++
CXXFLAGS=-I/usr/local/include -std=c++14 -g -Wall -Werror
LDFLAGS=-L/usr/local/lib -std=c++14 -pthread
LDLIBRARIES=-levent -lphosg -lz
EXECUTABLE=fastweb

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(LDLIBRARIES) -o $(EXECUTABLE)

clean:
	rm -rf *.dSYM *.o $(EXECUTABLE) $(EXECUTABLE)

.PHONY: clean
