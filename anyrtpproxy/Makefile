C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread

OBJS = anyrtpproxy.o \
       ../signalController.o \
       ../PracticalSocket.o \
       ../log.o \
       ../buffer.o \
       ../rtpSessionTable.o \
       ../rtpSession.o \
       options.o

EXECUTABLE = anyrtpproxy

all: $(EXECUTABLE)

anyrtpproxy: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

anyrtpproxy.o: anyrtpproxy.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

