C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -O2 -ldl

OPENVPNDEPS = openvpn/tun.o \
              openvpn/error.o \
              openvpn/socket.o \
              openvpn/buffer.o \
              openvpn/misc.o \
              openvpn/manage.o \
              openvpn/fdmisc.o \
              openvpn/otime.o \
              openvpn/options.o \
              openvpn/mtu.o \
              openvpn/plugin.o \
              openvpn/sig.o \
              openvpn/proxy.o \
              openvpn/socks.o \
              openvpn/status.o \
              openvpn/event.o \
              openvpn/route.o \
              openvpn/helper.o \
              openvpn/init.o \
              openvpn/interval.o \
              openvpn/base64.o \
              openvpn/shaper.o \
              openvpn/fragment.o



OBJS = anytun.o tunDevice.o buffer.o cypher.o authAlgo.o $(OPENVPNDEPS)
EXECUTABLE = anytun

all: $(EXECUTABLE)

anytun: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(C++) $(CCFLAGS) $< -c

buffer.o: buffer.cpp buffer.h
	$(C++) $(CCFLAGS) $< -c

cypher.o: cypher.cpp cypher.h buffer.h
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(C++) $(CCFLAGS) $< -c

anytun.o: anytun.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
