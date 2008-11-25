##
##  anytun
##
##  The secure anycast tunneling protocol (satp) defines a protocol used
##  for communication between any combination of unicast and anycast
##  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
##  mode and allows tunneling of every ETHER TYPE protocol (e.g.
##  ethernet, ip, arp ...). satp directly includes cryptography and
##  message authentication based on the methodes used by SRTP.  It is
##  intended to deliver a generic, scaleable and secure solution for
##  tunneling and relaying of packets of any protocol.
##
##
##  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
##                          Christian Pointner <satp@wirdorange.org>
##
##  This file is part of Anytun.
##
##  Anytun is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License version 3 as
##  published by the Free Software Foundation.
##
##  Anytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
##
TARGET=$(shell uname -s)
CC = gcc
CCFLAGS = -g
CXX = g++
CXXFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -Wall -O2 -lboost_thread -lgcrypt -lgpg-error -lboost_serialization -lboost_system

ifeq ($(TARGET),Linux)
  CCFLAGS += -D_XOPEN_SOURCE=600
  CXXFLAGS += -D_XOPEN_SOURCE=600
  LDFLAGS += -ldl
endif
ifeq ($(TARGET),OpenBSD)
  CXXFLAGS += -I/usr/local/include
  LDFLAGS += -L/usr/local/lib
endif

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
			 router.o \
			 routingTable.o \
       signalController.o \
       log.o \
       options.o \
       seqWindow.o \
       syncQueue.o \
			 syncCommand.o \
       syncRouteCommand.o \
       syncRtpCommand.o \
       syncConnectionCommand.o \
			 rtpSessionTable.o \
			 rtpSession.o \
       anyrtpproxy/callIdQueue.o

SYNCOBJS= syncServer.o \
       syncClient.o \
       syncTcpConnection.o

ANYCTROBJS = signalController.o \
							anyCtrOptions.o \
						 log.o \
						 syncTcpConnection.o \
						 syncServer.o

ANYCONFOBJS = log.o \
						 buffer.o \
						 keyDerivation.o \
						 mpi.o \
						 keyDerivationFactory.o \
						 networkAddress.o \
						 networkPrefix.o \
						 connectionList.o \
						 connectionParam.o \
						 rtpSessionTable.o \
						 rtpSession.o \
						 anyrtpproxy/callIdQueue.o \
						 syncRtpCommand.o \
						 anyConfOptions.o \
						 router.o \
						 routingTable.o \
						 seqWindow.o \
						 syncQueue.o \
						 syncBuffer.o \
						 syncCommand.o \
						 syncServer.o \
             syncTcpConnection.o \
						 syncRouteCommand.o \
						 syncConnectionCommand.o

EXECUTABLE = anytun anytun-config anytun-controld anytun-showtables

all: $(EXECUTABLE) libAnysync.a #anyrtpproxy

anytun: $(OBJS) $(SYNCOBJS) anytun.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS)

anytun-nosync: $(OBJS) anytun-nosync.o
	$(LD) $(OBJS) anytun-nosync.o -o $@ $(LDFLAGS)

anytun-showtables: $(OBJS) $(SYNCOBJS) anytun-showtables.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anytun-config: $(ANYCONFOBJS) anytun-config.o
	$(LD) $(ANYCONFOBJS) anytun-config.o -o $@ $(LDFLAGS)

anytun-controld: $(ANYCTROBJS) anytun-controld.o
	$(LD) $(ANYCTROBJS) anytun-controld.o -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(CXX) $(CXXFLAGS) $< -c

packetSource.o: packetSource.cpp packetSource.h
	$(CXX) $(CXXFLAGS) $< -c

buffer.o: buffer.cpp buffer.h
	$(CXX) $(CXXFLAGS) $< -c

syncBuffer.o: syncBuffer.cpp syncBuffer.h
	$(CXX) $(CXXFLAGS) $< -c

syncServer.o: syncServer.cpp syncServer.h
	$(CXX) $(CXXFLAGS) $< -c

syncClient.o: syncClient.cpp syncClient.h
	$(CXX) $(CXXFLAGS) $< -c

syncTcpConnection.o: syncTcpConnection.cpp syncTcpConnection.h
	$(CXX) $(CXXFLAGS) $< -c

controldTcpConnection.cpp: controldTcpConnection.cpp syncTcpConnection.h
	$(CXX) $(CXXFLAGS) $< -c

rtpSessionTable.o: rtpSessionTable.cpp rtpSessionTable.h
	$(CXX) $(CXXFLAGS) $< -c

rtpSession.o: rtpSession.cpp rtpSession.h
	$(CXX) $(CXXFLAGS) $< -c

plainPacket.o: plainPacket.cpp plainPacket.h buffer.h
	$(CXX) $(CXXFLAGS) $< -c

encryptedPacket.o: encryptedPacket.cpp encryptedPacket.h buffer.h
	$(CXX) $(CXXFLAGS) $< -c

cipher.o: cipher.cpp cipher.h buffer.h 
	$(CXX) $(CXXFLAGS) $< -c

anyCtrSocket.o: anyCtrSocket.cpp anyCtrSocket.h 
	$(CXX) $(CXXFLAGS) $< -c

anyCtrOptions.o: anyCtrOptions.cpp anyCtrOptions.h
	$(CXX) $(CXXFLAGS) $< -c

anyConfOptions.o: anyConfOptions.cpp anyConfOptions.h
	$(CXX) $(CXXFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(CXX) $(CXXFLAGS) $< -c

keyDerivation.o: keyDerivation.cpp keyDerivation.h
	$(CXX) $(CXXFLAGS) $< -c

mpi.o: mpi.cpp mpi.h
	$(CXX) $(CXXFLAGS) $< -c

cipherFactory.o: cipherFactory.cpp cipherFactory.h cipher.h
	$(CXX) $(CXXFLAGS) $< -c

authAlgoFactory.o: authAlgoFactory.cpp authAlgoFactory.h authAlgo.h
	$(CXX) $(CXXFLAGS) $< -c

keyDerivationFactory.o: keyDerivationFactory.cpp keyDerivationFactory.h keyDerivation.h
	$(CXX) $(CXXFLAGS) $< -c

routingTable.o: routingTable.cpp routingTable.h
	$(CXX) $(CXXFLAGS) $< -c

syncCommand.o: syncCommand.cpp syncCommand.h
	$(CXX) $(CXXFLAGS) $< -c

syncRouteCommand.o: syncRouteCommand.cpp syncRouteCommand.h
	$(CXX) $(CXXFLAGS) $< -c

syncRtpCommand.o: syncRtpCommand.cpp syncRtpCommand.h
	$(CXX) $(CXXFLAGS) $< -c

syncConnectionCommand.o: syncConnectionCommand.cpp syncConnectionCommand.h
	$(CXX) $(CXXFLAGS) $< -c

syncQueue.o: syncQueue.cpp syncQueue.h
	$(CXX) $(CXXFLAGS) $< -c

signalController.o: signalController.cpp signalController.h
	$(CXX) $(CXXFLAGS) $< -c

PracticalSocket.o: PracticalSocket.cpp PracticalSocket.h
	$(CXX) $(CXXFLAGS) $< -c

log.o: log.cpp log.h
	$(CXX) $(CXXFLAGS) $< -c

options.o: options.cpp options.h
	$(CXX) $(CXXFLAGS) $< -c

seqWindow.o: seqWindow.cpp seqWindow.h
	$(CXX) $(CXXFLAGS) $< -c

connectionList.o: connectionList.cpp connectionList.h
	$(CXX) $(CXXFLAGS) $< -c

connectionParam.o: connectionParam.cpp connectionParam.h
	$(CXX) $(CXXFLAGS) $< -c

networkPrefix.o: networkPrefix.cpp networkPrefix.h
	$(CXX) $(CXXFLAGS) $< -c

networkAddress.o: networkAddress.cpp networkAddress.h
	$(CXX) $(CXXFLAGS) $< -c

router.o: router.cpp router.h
	$(CXX) $(CXXFLAGS) $< -c

anytun.o: anytun.cpp
	$(CXX) $(CXXFLAGS) $< -c

anytun-nosync.o: anytun.cpp
	$(CXX) $(CXXFLAGS) -DANYTUN_NOSYNC $< -c -o anytun-nosync.o

anytun-showtables.o: anytun-showtables.cpp
	$(CXX) $(CXXFLAGS) $< -c

anytun-config.o: anytun-config.cpp
	$(CXX) $(CXXFLAGS) $< -c

anytun-controld.o: anytun-controld.cpp
	$(CXX) $(CXXFLAGS) $< -c

cConnectionParam.o: cConnectionParam.cpp
	$(CXX) $(CXXFLAGS) $< -c

libAnysync.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

anyrtpproxy: anytun
	@cd anyrtpproxy ; $(MAKE)

distclean: cleanall
	find . -name *.o -exec rm -f {} \;
	rm -f config.sub config.guess
	rm -f tunDevice.cpp tunDevice.h

cleanall: clean
	$(MAKE) --directory=$(CURDIR)/man clean

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

