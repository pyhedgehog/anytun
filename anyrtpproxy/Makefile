C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread

OBJS = anyrtpproxy.o \
       signalController.o \
       PracticalSocket.o \
       log.o \
       buffer.o \
       options.o

EXECUTABLE = anyrtpproxy

all: $(EXECUTABLE)

anyrtpproxy: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

signalController.o: ../signalController.cpp ../signalController.h
	$(C++) $(CCFLAGS) $< -c

PracticalSocket.o: ../PracticalSocket.cpp ../PracticalSocket.h
	$(C++) $(CCFLAGS) $< -c

log.o: ../log.cpp ../log.h
	$(C++) $(CCFLAGS) $< -c

buffer.o: ../buffer.cpp ../buffer.h
	$(C++) $(CCFLAGS) $< -c

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

anyrtpproxy.o: anyrtpproxy.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

