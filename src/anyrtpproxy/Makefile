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
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  any later version.
##
##  Anytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
##
CC = gcc
CFLAGS = -g -Wall
CXX = g++
CXXFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -Wall -O2 -lboost_thread -lboost_serialization -lboost_system

OBJS = anyrtpproxy.o \
       ../signalController.o \
       ../log.o \
       ../buffer.o \
       rtpSessionTable.o \
       rtpSession.o \
       connectionList.o \
       ../syncServer.o \
       ../syncClient.o \
       ../syncTcpConnection.o \
       ../syncQueue.o \
       syncRtpCommand.o \
       commandHandler.o \
       portWindow.o \
       callIdQueue.o \
       options.o

SRCS = $(OBJS:%.o=%.cpp)

EXECUTABLE = anyrtpproxy
DEPENDFILE = .depend

.PHONY: dep clean

all: dep $(EXECUTABLE)

dep: $(SRCS)
	$(CC) -MM $(SRCS) > $(DEPENDFILE)

-include $(DEPENDFILE)

anyrtpproxy: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(DEPENDFILE)
	rm -f $(EXECUTABLE)

