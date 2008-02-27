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
       syncCommand.o \
       syncRouteCommand.o \
       syncConnectionCommand.o \
			 plainPacket.o \
			 encryptedPacket.o \
       cipher.o \
       authAlgo.o \
			 authTag.o \
			 keyDerivation.o \
			 mpi.o \
			 cipherFactory.o \
			 authAlgoFactory.o \
			 keyDerivationFactory.o \
			 connectionList.o \
			 connectionParam.o \
			 networkAddress.o \
			 networkPrefix.o \
       PracticalSocket.o \
			 router.o \
			 routingTable.o \
			 routingTableEntry.o \
       signalController.o \
       syncSocket.o \
       syncSocketHandler.o \
       syncClientSocket.o \
       syncQueue.o \
       log.o \
       options.o \
       seqWindow.o \
       $(OPENVPNDEPS) \
			 $(SOCKETDEPS)

EXECUTABLE = anytun

all: $(EXECUTABLE) libAnysync.a

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

plainPacket.o: plainPacket.cpp plainPacket.h buffer.h
	$(C++) $(CCFLAGS) $< -c

encryptedPacket.o: encryptedPacket.cpp encryptedPacket.h buffer.h
	$(C++) $(CCFLAGS) $< -c

cipher.o: cipher.cpp cipher.h buffer.h 
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(C++) $(CCFLAGS) $< -c

authTag.o: authTag.cpp authTag.h buffer.h
	$(C++) $(CCFLAGS) $< -c

keyDerivation.o: keyDerivation.cpp keyDerivation.h
	$(C++) $(CCFLAGS) $< -c

mpi.o: mpi.cpp mpi.h
	$(C++) $(CCFLAGS) $< -c

cipherFactory.o: cipherFactory.cpp cipherFactory.h cipher.h
	$(C++) $(CCFLAGS) $< -c

authAlgoFactory.o: authAlgoFactory.cpp authAlgoFactory.h authAlgo.h
	$(C++) $(CCFLAGS) $< -c

keyDerivationFactory.o: keyDerivationFactory.cpp keyDerivationFactory.h keyDerivation.h
	$(C++) $(CCFLAGS) $< -c

routingTable.o: routingTable.cpp routingTable.h
	$(C++) $(CCFLAGS) $< -c

routingTableEntry.o: routingTableEntry.cpp routingTableEntry.h
	$(C++) $(CCFLAGS) $< -c

syncSocket.o: syncSocket.cpp syncSocket.h
	$(C++) $(CCFLAGS) $< -c

syncSocketHandler.o: syncSocketHandler.cpp syncSocketHandler.h
	$(C++) $(CCFLAGS) $< -c

syncCommand.o: syncCommand.cpp syncCommand.h
	$(C++) $(CCFLAGS) $< -c

syncRouteCommand.o: syncRouteCommand.cpp syncRouteCommand.h
	$(C++) $(CCFLAGS) $< -c

syncConnectionCommand.o: syncConnectionCommand.cpp syncConnectionCommand.h
	$(C++) $(CCFLAGS) $< -c

syncClientSocket.o: syncClientSocket.cpp syncClientSocket.h
	$(C++) $(CCFLAGS) $< -c

syncQueue.o: syncQueue.cpp syncQueue.h
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

networkPrefix.o: networkPrefix.cpp networkPrefix.h
	$(C++) $(CCFLAGS) $< -c

networkAddress.o: networkAddress.cpp networkAddress.h
	$(C++) $(CCFLAGS) $< -c

router.o: router.cpp router.h
	$(C++) $(CCFLAGS) $< -c

anytun.o: anytun.cpp
	$(C++) $(CCFLAGS) $< -c

cConnectionParam.o: cConnectionParam.cpp
	$(C++) $(CCFLAGS) $< -c

libAnysync.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	rm -f -r doc/html/*
	rm -f -r doc/latex/*

doxygen:
	doxygen Doxyfile

ctags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q .

