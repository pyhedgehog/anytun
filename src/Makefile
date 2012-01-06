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

ANYTUNOBJS := packetSource.o \
              authAlgo.o \
              authAlgoFactory.o \
              cipher.o \
              cipherFactory.o \
              plainPacket.o \
              encryptedPacket.o \
              options.o \
              signalController.o \
              sysExec.o \
              resolver.o \
              buffer.o \
              syncBuffer.o \
              keyDerivation.o \
              keyDerivationFactory.o \
              connectionList.o \
              connectionParam.o \
              networkAddress.o \
              networkPrefix.o \
              routingTable.o \
              routingTreeNode.o \
              log.o \
              logTargets.o \
              anytunError.o \
              seqWindow.o

ifneq ($(TARGET),mingw)
ANYTUNOBJS := $(ANYTUNOBJS) \
              tunDevice.o \
              daemonService.o
else
ANYTUNOBJS := $(ANYTUNOBJS) \
              win32/tunDevice.o \
              nullDaemon.o \
              win32/winService.o \
              win32/registryKey.o
endif


ANYSHOWOBJS := buffer.o \
               syncBuffer.o \
               keyDerivation.o \
               keyDerivationFactory.o \
               connectionList.o \
               connectionParam.o \
               networkAddress.o \
               networkPrefix.o \
               routingTable.o \
               routingTreeNode.o \
               log.o \
               logTargets.o \
               anytunError.o \
               seqWindow.o \
               nullOptions.o \
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

ifneq ($(TARGET),mingw)
ANYCTROBJS := $(ANYCTROBJS) \
              daemonService.o
else
ANYCTROBJS := $(ANYCTROBJS) \
              nullDaemon.o
endif


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

ifneq ($(TARGET),mingw)
  EXE :=
else
  EXE := .exe
endif

EXECUTABLES := anytun$(EXE) anytun-config$(EXE) anytun-controld$(EXE) anytun-showtables$(EXE) anytun-nosync$(EXE)
EXEOBJS := anytun.o anytun-config.o anytun-controld.o anytun-showtables.o

ANYTUNSRCS := $(ANYTUNOBJS:%.o=%.cpp)
ANYSHOWSRCS := $(ANYSHOWOBJS:%.o=%.cpp)
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
-include $(ANYTUNSRCS:%.cpp=%.d) $(ANYSHOWSRCS:%.cpp=%.d) $(SYNCSRCS:%.cpp=%.d) $(ANYCTRSRCS:%.cpp=%.d) $(ANYCONFSRCS:%.cpp=%.d) $(EXESRCS:%.cpp=%.d)
endif

strip: $(EXECUTABLES)
	$(STRIP) -s $(EXECUTABLES) 

anytun$(EXE): $(ANYTUNOBJS) $(SYNCOBJS) anytun.o
	$(LD) $(ANYTUNOBJS) $(SYNCOBJS) anytun.o -o $@ $(LDFLAGS)

anytun-static: $(ANYTUNOBJS) $(SYNCOBJS) anytun-noprivdrop.o
	$(LD) $(ANYTUNOBJS) $(SYNCOBJS) anytun-noprivdrop.o -o $@ -Bstatic -lstdc++ -static $(LDFLAGS) -lpthread
	$(STRIP) -s anytun-static

anytun-nosync$(EXE): $(ANYTUNOBJS) anytun-nosync.o
	$(LD) $(ANYTUNOBJS) anytun-nosync.o -o $@ $(LDFLAGS)

anytun-nosync.o: anytun.cpp
	$(CXX) $(CXXFLAGS) -DANYTUN_NOSYNC $< -c -o anytun-nosync.o

anytun-showtables$(EXE): $(ANYSHOWOBJS) $(SYNCOBJS) anytun-showtables.o
	$(LD) $(ANYSHOWOBJS) $(SYNCOBJS) anytun-showtables.o -o $@ $(LDFLAGS)

anytun-config$(EXE): $(ANYCONFOBJS) anytun-config.o
	$(LD) $(ANYCONFOBJS) anytun-config.o -o $@ $(LDFLAGS)

anytun-controld$(EXE): $(ANYCTROBJS) anytun-controld.o
	$(LD) $(ANYCTROBJS) anytun-controld.o -o $@ $(LDFLAGS)


options.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYTUN_OPTIONS $< -c -o $@

anyCtrOptions.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYCTR_OPTIONS $< -c -o $@

anyConfOptions.o: options.cpp 
	$(CXX) $(CXXFLAGS) -DANYCONF_OPTIONS $< -c -o $@

nullOptions.o: options.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@


libAnysync.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

anyrtpproxy: anytun
	$(MAKE) --directory=$(CURDIR)/anyrtpproxy


distclean: cleanall
	find . -name *.o -exec rm -f {} \;
	rm -f config.sub config.guess
	rm -f daemonService.h
	rm -f daemonService.cpp
	rm -f signalHandler.hpp
	rm -f sysExec.hpp
	rm -f version.h
	rm -f tunDevice.cpp
	rm -f include.mk

cleanall: clean
	$(MAKE) --directory="../doc" clean

clean:
	rm -f *.o
	rm -f *.d
	rm -f *.d.*
	rm -f win32/*.o
	rm -f win32/*.d
	rm -f win32/*.d.*
	rm -f $(EXECUTABLES)
	rm -f *.exe
	rm -f anytun-nosync
	rm -f -r doc/html/*
	rm -f -r doc/latex/*
	rm -f libAnysync.a
	$(MAKE) --directory=$(CURDIR)/anyrtpproxy clean

manpage:
	$(MAKE) --directory="../doc" manpage


INSTALL_TARGETS := install-bin install-etc
REMOVE_TARGETS := remove-bin remove-etc

ifdef MANDIR
INSTALL_TARGETS += install-man
REMOVE_TARGETS += remove-man
endif

ifdef EXAMPLESDIR
INSTALL_TARGETS += install-examples
REMOVE_TARGETS += remove-examples
endif

install: all $(INSTALL_TARGETS)

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
	@ sed -e 's#DAEMON=/usr/sbin/anytun#DAEMON=$(SBINDIR)/anytun#'                               \
        -e 's#ANYTUNCONFIG=/usr/bin/anytun-config#ANYTUNCONFIG=$(BINDIR)/anytun-config#'       \
        -e 's#CONTROLDAEMON=/usr/bin/anytun-controld#CONTROLDAEMON=$(BINDIR)/anytun-controld#' \
        -e 's#CONFIG_DIR=/etc/anytun#CONFIG_DIR=$(ETCDIR)/anytun#' ../etc/init.d/anytun > ../etc/init.d/anytun.bak
	$(INSTALL) -m 755 ../etc/init.d/anytun.bak $(DESTDIR)$(ETCDIR)/init.d/anytun
	rm -f ../etc/init.d/anytun.bak

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
               $(INSTALL) -m 600 $$file $(DESTDIR)$(EXAMPLESDIR)/anytun/$$dir/conf.d ;       \
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
	$(INSTALL) -m 644 ../doc/anytun.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 ../doc/anytun-config.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 ../doc/anytun-controld.8 $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 ../doc/anytun-showtables.8 $(DESTDIR)$(MANDIR)/man8/

uninstall: remove


remove: $(REMOVE_TARGETS)

remove-bin:
	rm -f $(DESTDIR)$(SBINDIR)/anytun
	rm -f $(DESTDIR)$(BINDIR)/anytun-config
	rm -f $(DESTDIR)$(BINDIR)/anytun-controld
	rm -f $(DESTDIR)$(BINDIR)/anytun-showtables

remove-etc:
	rm -f $(DESTDIR)$(ETCDIR)/init.d/anytun

remove-examples:
	rm -rf $(DESTDIR)$(EXAMPLESDIR)/anytun/

remove-man:
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-config.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-controld.8
	rm -f $(DESTDIR)$(MANDIR)/man8/anytun-showtables.8

purge: remove
	rm -rf $(DESTDIR)$(ETCDIR)/anytun/
