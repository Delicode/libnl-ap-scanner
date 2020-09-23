EXECUTABLE=ap-scanner

DEFINES=
INCLUDES=

CPP=g++
GCC=gcc
CXXFLAGS=-std=c++14 -Wall -Wfloat-conversion -Wno-switch `pkg-config --cflags libnl-genl-3.0`
CFLAGS=-Wall -Wfloat-conversion -Wpedantic -Wno-switch `pkg-config --cflags libnl-genl-3.0`
LDFLAGS += `pkg-config --libs libnl-genl-3.0`

SOURCES_CXX=./main.cpp
SOURCES_C=

OBJECTS_CXX=$(SOURCES_CXX:.cpp=.o)
OBJECTS_C=$(SOURCES_C:.c=.o)

.PHONY: clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS_CXX) $(OBJECTS_C)
	$(CPP) -o $(EXECUTABLE) $(OBJECTS_CXX) $(OBJECTS_C) $(LDFLAGS)

%.o: %.cpp
	$(CPP) $(INCLUDES) $(DEFINES) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(GCC) $(INCLUDES) $(DEFINES) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ./*.o
	rm -f ./ap-scanner

