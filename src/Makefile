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

include include.mk

OBJS = tunDevice.o \
       packetSource.o \
       buffer.o \
       syncBuffer.o \
			 plainPacket.o \
			 encryptedPacket.o \
       cipher.o \
       authAlgo.o \
			 keyDerivation.o \
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
			 routingTreeNode.o \

SYNCOBJS= syncServer.o \
       syncClient.o \
       syncQueue.o \
			 syncCommand.o \
       syncRouteCommand.o \
       syncConnectionCommand.o \
       syncTcpConnection.o

ANYCTROBJS = signalController.o \
							anyCtrOptions.o \
						 log.o \
						 syncTcpConnection.o \
						 syncServer.o

ANYCONFOBJS = log.o \
						 buffer.o \
						 keyDerivation.o \
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

EXECUTABLE = anytun anytun-config anytun-controld anytun-showtables
EXEOBJS = anytun.o anytun-config.o anytun-controld.o anytun-showtables.o

SRCS = $(OBJS:%.o=%.cpp)
SYNCSRCS = $(SYNCOBJS:%.o=%.cpp)
ANYCTRSRCS = $(ANYCTROBJS:%.o=%.cpp)
ANYCONFSRCS = $(ANYCONFOBJS:%.o=%.cpp)
EXESRCS = $(EXEOBJS:%.o=%.cpp)

.PHONY: distclean cleanall clean ctags

all: $(EXECUTABLE) #libAnysync.a 

%.d: %.cpp
	@set -e; rm -f $@; \
	 $(CXX) -MM $(CXXFLAGS) $< > $@.$$$$; \
   sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
   rm -f $@.$$$$; echo '(re)building $@'

-include $(SRCS:%.cpp=%.d) $(SYNCSRCS:%.cpp=%.d) $(ANYCTRSRCS:%.cpp=%.d) $(ANYCONFSRCS:%.cpp=%.d) $(EXESRCS:%.cpp=%.d)

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
	rm -f include.mk

cleanall: clean
	$(MAKE) --directory=$(CURDIR)/man clean

clean:
	rm -f *.o
	rm -f *.d
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
