TARGET=$(shell uname -s)
C = gcc
CFLAGS = -g
CFLAGS += -DSOCKETS_NAMESPACE=sockets
CFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
C++ = g++
CCFLAGS = -g -Wall
CCFLAGS += -DSOCKETS_NAMESPACE=sockets
CCFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread -lgcrypt -lgpg-error -lboost_serialization

ifeq ($(TARGET),Linux)
  LDFLAGS += -ldl
endif
ifeq ($(TARGET),OpenBSD)
  CCFLAGS += -I/usr/local/include
  LDFLAGS += -L/usr/local/lib
endif

ifndef NOOVPN
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
endif

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
			 plainPacket.o \
			 encryptedPacket.o \
       cipher.o \
       authAlgo.o \
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
       signalController.o \
       syncQueue.o \
       log.o \
       options.o \
       seqWindow.o \
			 syncCommand.o \
       syncRouteCommand.o \
       syncRtpCommand.o \
       syncConnectionCommand.o \
			 rtpSessionTable.o \
			 rtpSession.o \
       anyrtpproxy/callIdQueue.o \
       $(OPENVPNDEPS)

SYNCOBJS= syncSocket.o \
       syncSocketHandler.o \
       syncClientSocket.o \
			 $(SOCKETDEPS)

ANYCTROBJS = anyCtrSocket.o \
						 anyCtrOptions.o \
						 signalController.o \
						 log.o \
						 $(SOCKETDEPS)

ANYCONFOBJS = log.o \
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
						 anyrtpproxy/callIdQueue.o \
						 syncRtpCommand.o \
						 PracticalSocket.o \
						 anyConfOptions.o \
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

EXECUTABLE = anytun anytun-config anytun-controld anytun-showtables manpage

all: $(EXECUTABLE) libAnysync.a anyrtpproxy

anytun: $(OBJS) $(SYNCOBJS) anytun.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS)

anytun-nosync: $(OBJS) anytun-nosync.o
	$(LD) $(OBJS) anytun-nosync.o -o $@ $(LDFLAGS)

anytun-showtables: $(OBJS) anytun-showtables.o
	$(LD) $(OBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anytun-config: $(ANYCONFOBJS) anytun-config.o
	$(LD) $(ANYCONFOBJS) anytun-config.o -o $@ $(LDFLAGS)

anytun-controld: $(ANYCTROBJS) anytun-controld.o
	$(LD) $(ANYCTROBJS) anytun-controld.o -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(C++) $(CCFLAGS) $< -c

Sockets/libSockets.a:
	$(MAKE) --directory=./Sockets

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

anyCtrSocket.o: anyCtrSocket.cpp anyCtrSocket.h 
	$(C++) $(CCFLAGS) $< -c

anyCtrOptions.o: anyCtrOptions.cpp anyCtrOptions.h
	$(C++) $(CCFLAGS) $< -c

anyConfOptions.o: anyConfOptions.cpp anyConfOptions.h
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

anytun-nosync.o: anytun.cpp
	$(C++) $(CCFLAGS) -DANYTUN_NOSYNC $< -c -o anytun-nosync.o

anytun-showtables.o: anytun-showtables.cpp
	$(C++) $(CCFLAGS) $< -c

anytun-config.o: anytun-config.cpp
	$(C++) $(CCFLAGS) $< -c

anytun-controld.o: anytun-controld.cpp
	$(C++) $(CCFLAGS) $< -c

cConnectionParam.o: cConnectionParam.cpp
	$(C++) $(CCFLAGS) $< -c

libAnysync.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

anyrtpproxy: anytun
	@cd anyrtpproxy ; $(MAKE)

distclean: cleanall
ifndef NOOVPN
	$(MAKE) --directory=$(CURDIR)/openvpn distclean
endif
	find . -name *.o -exec rm -f {} \;
	rm -f config.sub config.guess
	rm -f tunDevice.cpp tunDevice.h

cleanall: clean
	$(MAKE) --directory=$(CURDIR)/man clean
	$(MAKE) --directory=$(CURDIR)/Sockets clean
ifndef NOOVPN
	$(MAKE) --directory=$(CURDIR)/openvpn clean
endif
	rm -f Sockets/libSockets.a Sockets/Sockets-config

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	rm -f anytun-nosync
	rm -f -r doc/html/*
	rm -f -r doc/latex/*
	rm -f libAnysync.a
	$(MAKE) --directory=$(CURDIR)/anyrtpproxy clean

manpage:
	@cd man ; $(MAKE)

doxygen:
	doxygen Doxyfile

ctags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q .

