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
C = gcc
CFLAGS = -g -Wall
CFLAGS += -DSOCKETS_NAMESPACE=sockets
CFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
C++ = g++
CCFLAGS = -g -Wall
CCFLAGS += -DSOCKETS_NAMESPACE=sockets
CCFLAGS += -DSOCKETS_NAMESPACE_STR='"sockets"'
LD = g++
LDFLAGS = -g -Wall -O2 -lpthread -lssl -lboost_serialization

OBJS = anyrtpproxy.o \
       ../signalController.o \
       ../PracticalSocket.o \
       ../log.o \
       ../buffer.o \
       ../rtpSessionTable.o \
       ../rtpSession.o \
       connectionList.o \
       ../syncSocketHandler.o \
       ../syncClientSocket.o \
       ../syncQueue.o \
       ../syncSocket.o \
       ../seqWindow.o \
       ../connectionParam.o \
       ../routingTable.o \
       ../syncBuffer.o \
       ../syncCommand.o \
       ../syncRouteCommand.o \
       ../syncRtpCommand.o \
       ../syncConnectionCommand.o \
       ../networkAddress.o \
       ../networkPrefix.o \
       ../Sockets/libSockets.a \
       commandHandler.o \
       portWindow.o \
       callIdQueue.o \
       options.o

EXECUTABLE = anyrtpproxy

all: $(EXECUTABLE)

anyrtpproxy: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

portWindow.o: portWindow.cpp portWindow.h
	$(C++) $(CCFLAGS) $< -c

connectionList.o: connectionList.cpp connectionList.h
	$(C++) $(CCFLAGS) $< -c

commandHandler.o: commandHandler.cpp commandHandler.h
	$(C++) $(CCFLAGS) $< -c

callIdQueue.o: callIdQueue.cpp callIdQueue.h
	$(C++) $(CCFLAGS) $< -c

anyrtpproxy.o: anyrtpproxy.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

