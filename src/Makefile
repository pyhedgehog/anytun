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
##  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl, 
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

ifneq ($(MAKECMDGOALS),distclean)
include include.mk
endif

OBJS := tunDevice.o \
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
        logTargets.o \
        sysExec.o \
        anytunError.o \
        options.o \
        seqWindow.o \
        routingTreeNode.o \
        resolver.o

SYNCOBJS := syncServer.o \
            syncClient.o \
            syncQueue.o \
            syncCommand.o \
            syncRouteCommand.o \
            syncConnectionCommand.o \
            syncTcpConnection.o

ANYCTROBJS := signalController.o \
              anyCtrOptions.o \
              buffer.o \
              log.o \
              logTargets.o \
              anytunError.o \
              syncTcpConnection.o \
              syncServer.o \
              resolver.o

ANYCONFOBJS := log.o \
               logTargets.o \
               anytunError.o \
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
               syncConnectionCommand.o \
               resolver.o

EXECUTABLES := anytun anytun-config anytun-controld anytun-showtables anytun-nosync
EXEOBJS := anytun.o anytun-config.o anytun-controld.o anytun-showtables.o

SRCS := $(OBJS:%.o=%.cpp)
SYNCSRCS := $(SYNCOBJS:%.o=%.cpp)
ANYCTRSRCS := $(ANYCTROBJS:%.o=%.cpp)
ANYCONFSRCS := $(ANYCONFOBJS:%.o=%.cpp)
EXESRCS := $(EXEOBJS:%.o=%.cpp)

.PHONY: distclean cleanall clean manpage install install-bin install-etc install-man uninstall remove purge

all: $(EXECUTABLES) #libAnysync.a 

%.d: %.cpp
	@set -e; rm -f $@;                                    \
   $(CXX) -MM $(CXXFLAGS) $< > $@.$$$$;                 \
   sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@;  \
   rm -f $@.$$$$; echo '(re)building $@'

ifneq ($(MAKECMDGOALS),distclean)
-include $(SRCS:%.cpp=%.d) $(SYNCSRCS:%.cpp=%.d) $(ANYCTRSRCS:%.cpp=%.d) $(ANYCONFSRCS:%.cpp=%.d) $(EXESRCS:%.cpp=%.d)
endif

strip: $(EXECUTABLES)
	$(STRIP) -s $(EXECUTABLES) 

anytun: $(OBJS) $(SYNCOBJS) anytun.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS)

anytun-static: $(OBJS) $(SYNCOBJS) anytun-noprivdrop.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun-noprivdrop.o -o $@ -Bstatic -lstdc++ -static $(LDFLAGS) -lpthread
	$(STRIP) -s anytun-static

anytun-nosync: $(OBJS) anytun-nosync.o
	$(LD) $(OBJS) anytun-nosync.o -o $@ $(LDFLAGS)

anytun-nosync.o: anytun.cpp
	$(CXX) $(CXXFLAGS) -DANYTUN_NOSYNC $< -c -o anytun-nosync.o

anytun-noprivdrop.o: anytun.cpp
	$(CXX) $(CXXFLAGS) -DNO_PRIVDROP $< -c -o anytun-noprivdrop.o

anytun-showtables: $(OBJS) $(SYNCOBJS) anytun-showtables.o
	$(LD) $(OBJS) $(SYNCOBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anytun-config: $(ANYCONFOBJS) anytun-config.o
	$(LD) $(ANYCONFOBJS) anytun-config.o -o $@ $(LDFLAGS)

anytun-controld: $(ANYCTROBJS) anytun-controld.o
	$(LD) $(ANYCTROBJS) anytun-controld.o -o $@ $(LDFLAGS)


options.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYTUN_OPTIONS $< -c -o $@

anyCtrOptions.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYCTR_OPTIONS $< -c -o $@

anyConfOptions.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYCONF_OPTIONS $< -c -o $@

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
	rm -f *.d.*
	rm -f $(EXECUTABLES)
	rm -f anytun-nosync
	rm -f -r doc/html/*
	rm -f -r doc/latex/*
	rm -f libAnysync.a
	$(MAKE) --directory=$(CURDIR)/anyrtpproxy clean

manpage:
	@cd man ; $(MAKE)

install: all install-bin install-etc install-examples install-man

install-bin: $(EXECUTABLES)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 anytun $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 anytun-config $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 anytun-controld $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 anytun-showtables $(DESTDIR)$(BINDIR)

install-etc:
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/anytun
	@ echo "example configurations can be found at $(EXAMPLESDIR)/anytun" > $(DESTDIR)$(ETCDIR)/anytun/README
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/init.d
	$(INSTALL) -m 755 ../etc/init.d/anytun $(DESTDIR)$(ETCDIR)/init.d/anytun
	@ sed -i 's#DAEMON=/usr/sbin/anytun#DAEMON=$(SBINDIR)/anytun#' $(DESTDIR)$(ETCDIR)/init.d/anytun
	@ sed -i 's#ANYTUNCONFIG=/usr/bin/anytun-config#ANYTUNCONFIG=$(BINDIR)/anytun-config#' $(DESTDIR)$(ETCDIR)/init.d/anytun
	@ sed -i 's#CONTROLDAEMON=/usr/bin/anytun-controld#CONTROLDAEMON=$(BINDIR)/anytun-controld#' $(DESTDIR)$(ETCDIR)/init.d/anytun
	@ sed -i 's#CONFIG_DIR=/etc/anytun#CONFIG_DIR=$(ETCDIR)/anytun#' $(DESTDIR)$(ETCDIR)/init.d/anytun

install-examples:
	$(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/anytun
	$(INSTALL) -m 644 ../etc/anytun/autostart $(DESTDIR)$(EXAMPLESDIR)/anytun/autostart
	@( cd '../etc/anytun/' ;                                                                   \
     for dir in `ls`; do                                                                     \
       if [ -d $$dir ]; then                                                                 \
         echo "install $$dir configuration" ;                                                \
         cd $$dir ;                                                                          \
         $(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir ;                               \
         $(INSTALL) -m 600 config $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir/config ;             \
         if [ -e 'post-up.sh' ]; then                                                        \
           $(INSTALL) -m 755 post-up.sh $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir/post-up.sh ;   \
         fi ;                                                                                \
         if [ -d 'conf.d' ]; then                                                            \
           $(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir/conf.d ;                      \
           cd conf.d ;                                                                       \
           for file in `ls`; do                                                              \
             if [ -f $$file ]; then                                                          \
               $(INSTALL) -m 644 $$file $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir/conf.d ;       \
             fi ;                                                                            \
           done ;                                                                            \
           cd .. ;                                                                           \
         fi ;                                                                                \
         cd .. ;                                                                             \
       fi ;                                                                                  \
     done                                                                                    \
   )

install-man: manpage
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 man/anytun.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 man/anytun-config.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 man/anytun-controld.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 man/anytun-showtables.8 $(DESTDIR)$(MANDIR)/man8/

uninstall: remove

remove:
	rm -f $(DESTDIR)$(SBINDIR)/anytun
	rm -f $(DESTDIR)$(BINDIR)/anytun-config
	rm -f $(DESTDIR)$(BINDIR)/anytun-controld
	rm -f $(DESTDIR)$(BINDIR)/anytun-showtables
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-config.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-controld.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-showtables.8
	rm -f $(DESTDIR)$(ETCDIR)/init.d/anytun
	rm -rf $(DESTDIR)$(EXAMPLESDIR)/anytun/

purge: remove
	rm -rf $(DESTDIR)$(ETCDIR)/anytun/
