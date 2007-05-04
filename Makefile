C = gcc
C++ = g++
CCFLAGS = -Wall
LDFLAGS = #-lpthread #-static

OBJS = tunDevice.o tun.c
EXECUTABLE = anytun

all: $(EXECUTABLE)

anytun: $(OBJS)
	$(C++) $(OBJS) -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h openvpn/tun.h
	$(C++) $(CCFLAGS) $< -c

tun.o: openvpn/tun.c openvpn/tun.h
	$(C) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)