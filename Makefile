C = gcc
CFLAGS = -g -Wall
CFLAGS += -DSOCKETS_NAMESPACE=sockets
CFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
C++ = g++
CCFLAGS = -g -Wall
CCFLAGS += -DSOCKETS_NAMESPACE=sockets
CCFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
LD = g++
LDFLAGS = -g -Wall -O2 -ldl -lpthread -lgcrypt -lssl -lboost_serialization

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

SOCKETDEPS = Sockets/libSockets.a

#Sockets/TcpSocket.o \
#             Sockets/Socket.o \
#             Sockets/Thread.o \
#             Sockets/SocketHandler.o \
#             Sockets/Ipv4Address.o \
#             Sockets/Mutex.o \
#             Sockets/SSLInitializer.o


OBJS = anytun.o \
       tunDevice.o \
       packetSource.o \
       buffer.o \
       syncBuffer.o \
       packet.o \
       cypher.o \
       authAlgo.o \
			 authTag.o \
			 keyDerivation.o \
			 mpi.o \
			 connectionList.o \
			 connectionParam.o \
			 networkAddress.o \
       PracticalSocket.o \
			 router.o \
       signalController.o \
       syncSocket.o \
       log.o \
       options.o \
       seqWindow.o \
       $(OPENVPNDEPS) \
			 $(SOCKETDEPS)

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

syncBuffer.o: syncBuffer.cpp syncBuffer.h
	$(C++) $(CCFLAGS) $< -c

packet.o: packet.cpp packet.h buffer.h
	$(C++) $(CCFLAGS) $< -c

cypher.o: cypher.cpp cypher.h buffer.h 
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(C++) $(CCFLAGS) $< -c

authTag.o: authTag.cpp authTag.h buffer.h
	$(C++) $(CCFLAGS) $< -c

keyDerivation.o: keyDerivation.cpp keyDerivation.h
	$(C++) $(CCFLAGS) $< -c

mpi.o: mpi.cpp mpi.h
	$(C++) $(CCFLAGS) $< -c

syncSocket.o: syncSocket.cpp syncSocket.h
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

connectionList.o: connectionList.cpp connectionList.h
	$(C++) $(CCFLAGS) $< -c

connectionParam.o: connectionParam.cpp connectionParam.h
	$(C++) $(CCFLAGS) $< -c

networkAddress.o: networkAddress.cpp networkAddress.h
	$(C++) $(CCFLAGS) $< -c

router.o: router.cpp router.h
	$(C++) $(CCFLAGS) $< -c

anytun.o: anytun.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	rm -f -r doc/html/*
	rm -f -r doc/latex/*

doxygen:
	doxygen Doxyfile

ctags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q .

