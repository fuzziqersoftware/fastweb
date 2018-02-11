OBJECTS=MIMEType.o ResourceManager.o Main.o
CXX=g++
CXXFLAGS=-I/opt/local/include -std=c++14 -g -Wall -Werror
LDFLAGS=-L/opt/local/lib -std=c++14
LDLIBRARIES=-levent -lphosg -lz -lpthread
EXECUTABLE=fastweb

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(LDLIBRARIES) -o $(EXECUTABLE)

clean:
	rm -rf *.dSYM *.o $(EXECUTABLE) $(EXECUTABLE)

.PHONY: clean
