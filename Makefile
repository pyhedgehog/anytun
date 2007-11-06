C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -O2 -ldl -lpthread -lsrtp -lgcrypt

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

OBJS = anytun.o \
       tunDevice.o \
       packetSource.o \
       buffer.o \
       packet.o \
       cypher.o \
       authAlgo.o \
			 keyDerivation.o \
			 connectionList.o \
			 connectionParam.o \
			 networkAddress.o \
       PracticalSocket.o \
			 router.o \
       signalController.o \
       log.o \
       options.o \
       seqWindow.o \
       $(OPENVPNDEPS) 

EXECUTABLE = anytun

all: $(EXECUTABLE)

anytun: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(C++) $(CCFLAGS) $< -c

packetSource.o: packetSource.cpp packetSource.h
	$(C++) $(CCFLAGS) $< -c

buffer.o: buffer.cpp buffer.h
	$(C++) $(CCFLAGS) $< -c

packet.o: packet.cpp packet.h buffer.h
	$(C++) $(CCFLAGS) $< -c

cypher.o: cypher.cpp cypher.h buffer.h 
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(C++) $(CCFLAGS) $< -c

keyDerivation.o: keyDerivation.cpp keyDerivation.h
	$(C++) $(CCFLAGS) $< -c

signalController.o: signalController.cpp signalController.h
	$(C++) $(CCFLAGS) $< -c

PracticalSocket.o: PracticalSocket.cpp PracticalSocket.h
	$(C++) $(CCFLAGS) $< -c

log.o: log.cpp log.h
	$(C++) $(CCFLAGS) $< -c

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

seqWindow.o: seqWindow.cpp seqWindow.h
	$(C++) $(CCFLAGS) $< -c

anytun.o: anytun.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

doxygen:
	doxygen Doxyfile

