C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread

OBJS = plain_tool.o \
       signalController.o \
       PracticalSocket.o \
       log.o \
       options.o

EXECUTABLE = plain_tool

all: $(EXECUTABLE)

plain_tool: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

signalController.o: ../signalController.cpp ../signalController.h
	$(C++) $(CCFLAGS) $< -c

PracticalSocket.o: ../PracticalSocket.cpp ../PracticalSocket.h
	$(C++) $(CCFLAGS) $< -c

log.o: ../log.cpp ../log.h
	$(C++) $(CCFLAGS) $< -c

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

plain_tool.o: plain_tool.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

