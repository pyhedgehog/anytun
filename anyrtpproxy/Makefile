C = gcc
CFLAGS = -g -Wall
CFLAGS += -DSOCKETS_NAMESPACE=sockets
CFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
C++ = g++
CCFLAGS = -g -Wall
CCFLAGS += -DSOCKETS_NAMESPACE=sockets
CCFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
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

