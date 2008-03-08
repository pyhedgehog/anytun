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


OBJS = tunDevice.o \
       packetSource.o \
       buffer.o \
       syncBuffer.o \
       syncCommand.o \
       syncRouteCommand.o \
       syncRtpCommand.o \
       syncConnectionCommand.o \
			 plainPacket.o \
			 encryptedPacket.o \
       cipher.o \
       authAlgo.o \
			 keyDerivation.o \
			 rtpSessionTable.o \
			 rtpSession.o \
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

ANYMUXOBJS = muxSocket.o \
						 anymuxOptions.o \
						 signalController.o \
						 log.o \
						 $(SOCKETDEPS)

ANYCTROBJS = log.o \
						 buffer.o \
						 keyDerivation.o \
						 mpi.o \
						 keyDerivationFactory.o \
						 networkAddress.o \
						 networkPrefix.o \
						 signalController.o \
						 connectionList.o \
						 connectionParam.o \
			 rtpSessionTable.o \
			 rtpSession.o \
       syncRtpCommand.o \
						 anyctrOptions.o \
						 router.o \
						 routingTable.o \
						 seqWindow.o \
						 syncSocket.o \
						 syncSocketHandler.o \
						 syncClientSocket.o \
						 syncQueue.o \
						 syncBuffer.o \
						 syncCommand.o \
						 syncRouteCommand.o \
						 syncConnectionCommand.o \
						 $(SOCKETDEPS)

EXECUTABLE = anytun anyctr anymux anytun-showtables

all: $(EXECUTABLE) libAnysync.a

anytun: $(OBJS) anytun.o
	$(LD) $(OBJS) anytun.o -o $@ $(LDFLAGS)

anytun-showtables: $(OBJS) anytun-showtables.o
	$(LD) $(OBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anyctr: $(ANYCTROBJS) anyctr.o
	$(LD) $(ANYCTROBJS) anyctr.o -o $@ $(LDFLAGS)

anymux: $(ANYMUXOBJS) anymux.o
	$(LD) $(ANYMUXOBJS) anymux.o -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(C++) $(CCFLAGS) $< -c

packetSource.o: packetSource.cpp packetSource.h
	$(C++) $(CCFLAGS) $< -c

buffer.o: buffer.cpp buffer.h
	$(C++) $(CCFLAGS) $< -c

syncBuffer.o: syncBuffer.cpp syncBuffer.h
	$(C++) $(CCFLAGS) $< -c

rtpSessionTable.o: rtpSessionTable.cpp rtpSessionTable.h
	$(C++) $(CCFLAGS) $< -c

rtpSession.o: rtpSession.cpp rtpSession.h
	$(C++) $(CCFLAGS) $< -c

plainPacket.o: plainPacket.cpp plainPacket.h buffer.h
	$(C++) $(CCFLAGS) $< -c

encryptedPacket.o: encryptedPacket.cpp encryptedPacket.h buffer.h
	$(C++) $(CCFLAGS) $< -c

cipher.o: cipher.cpp cipher.h buffer.h 
	$(C++) $(CCFLAGS) $< -c

muxSocket.o: muxSocket.cpp muxSocket.h 
	$(C++) $(CCFLAGS) $< -c

anymuxOptions.o: anymuxOptions.cpp anymuxOptions.h
	$(C++) $(CCFLAGS) $< -c

anyctrOptions.o: anyctrOptions.cpp anyctrOptions.h
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
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

syncSocket.o: syncSocket.cpp syncSocket.h
	$(C++) $(CCFLAGS) $< -c

syncSocketHandler.o: syncSocketHandler.cpp syncSocketHandler.h
	$(C++) $(CCFLAGS) $< -c

syncCommand.o: syncCommand.cpp syncCommand.h
	$(C++) $(CCFLAGS) $< -c

syncRouteCommand.o: syncRouteCommand.cpp syncRouteCommand.h
	$(C++) $(CCFLAGS) $< -c

syncRtpCommand.o: syncRtpCommand.cpp syncRtpCommand.h
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

anytun-showtables.o: anytun-showtables.cpp
	$(C++) $(CCFLAGS) $< -c

anyctr.o: anyctr.cpp
	$(C++) $(CCFLAGS) $< -c

anymux.o: anymux.cpp
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

