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
CFLAGS = -g
CXX = g++
CXXFLAGS = -g -Wall -O2
LD = g++
LDFLAGS = -g -Wall -O2 -lboost_thread -lgcrypt -lgpg-error -lboost_serialization -lboost_system

ifeq ($(TARGET),Linux)
  CFLAGS += -D_XOPEN_SOURCE=600
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
			 routingTable.o \
       signalController.o \
       log.o \
       options.o \
       seqWindow.o \
			 syncCommand.o \
       syncRouteCommand.o \
       syncConnectionCommand.o \
			 routingTreeNode.o \

SYNCOBJS= syncServer.o \
       syncClient.o \
       syncQueue.o \
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
						 routingTreeNode.o \
						 anyConfOptions.o \
						 routingTable.o \
						 seqWindow.o \
						 syncQueue.o \
						 syncBuffer.o \
						 syncCommand.o \
						 syncServer.o \
             syncTcpConnection.o \
						 syncRouteCommand.o \
						 syncConnectionCommand.o

SRCS = $(OBJS:%.o=%.cpp)
SYNCSRCS = $(SYNCOBJS:%.o=%.cpp)
ANYCTRSRCS = $(ANYCTROBJS:%.o=%.cpp)
ANYCONFSRCS = $(ANYCONFOBJS:%.o=%.cpp)

EXECUTABLE = anytun anytun-config anytun-controld anytun-showtables
DEPENDFILE = .depend

.PHONY: dep distclean cleanall clean ctags

all: dep $(EXECUTABLE) #libAnysync.a 

dep: $(SRCS) $(SYNCSRCS) $(ANYCTRSRCS) $(ANYCONFSRCS)
	$(CC) -MM $(SRCS) $(SYNCSRCS) $(ANYCTRSRCS) $(ANYCONFSRCS) > $(DEPENDFILE)

-include $(DEPENDFILE)

anytun: $(OBJS) $(SYNCOBJS) anytun.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS)

anytun-static: $(OBJS) $(SYNCOBJS) anytun.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS) -lpthread -static
	strip -s anytun-static

anytun-nosync: $(OBJS) anytun-nosync.o
	$(LD) $(OBJS) anytun-nosync.o -o $@ $(LDFLAGS)

anytun-nosync.o: anytun.cpp anytun.o
	$(CXX) $(CXXFLAGS) -DANYTUN_NOSYNC $< -c -o anytun-nosync.o

anytun-showtables: $(OBJS) $(SYNCOBJS) anytun-showtables.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anytun-config: $(ANYCONFOBJS) anytun-config.o
	$(LD) $(ANYCONFOBJS) anytun-config.o -o $@ $(LDFLAGS)

anytun-controld: $(ANYCTROBJS) anytun-controld.o
	$(LD) $(ANYCTROBJS) anytun-controld.o -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -c

libAnysync.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

anyrtpproxy: anytun
	$(MAKE) --directory=$(CURDIR)/anyrtpproxy

distclean: cleanall
	find . -name *.o -exec rm -f {} \;
	rm -f config.sub config.guess
	rm -f tunDevice.cpp

cleanall: clean
	$(MAKE) --directory=$(CURDIR)/man clean

clean:
	rm -f *.o
	rm -f $(DEPENDFILE)
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
