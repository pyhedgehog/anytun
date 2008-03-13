C = gcc
CFLAGS = -g -Wall
CFLAGS += -DSOCKETS_NAMESPACE=sockets
CFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
C++ = g++
CCFLAGS = -g -Wall
CCFLAGS += -DSOCKETS_NAMESPACE=sockets
CCFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread -lssl -lboost_serialization

OBJS = anyrtpproxy.o \
       ../signalController.o \
       ../PracticalSocket.o \
       ../log.o \
       ../buffer.o \
       ../rtpSessionTable.o \
       ../rtpSession.o \
       connectionList.o \
       ../syncSocketHandler.o \
       ../syncClientSocket.o \
       ../syncQueue.o \
       ../syncSocket.o \
       ../seqWindow.o \
       ../connectionParam.o \
       ../routingTable.o \
       ../syncBuffer.o \
       ../syncCommand.o \
       ../syncRouteCommand.o \
       ../syncRtpCommand.o \
       ../syncConnectionCommand.o \
       ../networkAddress.o \
       ../networkPrefix.o \
       ../Sockets/libSockets.a \
       commandHandler.o \
       options.o

EXECUTABLE = anyrtpproxy

all: $(EXECUTABLE)

anyrtpproxy: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

connectionList.o: connectionList.cpp connectionList.h
	$(C++) $(CCFLAGS) $< -c

commandHandler.o: commandHandler.cpp commandHandler.h
	$(C++) $(CCFLAGS) $< -c

anyrtpproxy.o: anyrtpproxy.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

