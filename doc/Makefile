##
##  anytun
##
##  The secure anycast tunneling protocol (satp) defines a protocol used
##  for communication between any combination of unicast and anycast
##  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
##  mode and allows tunneling of every ETHER TYPE protocol (e.g.
##  ethernet, ip, arp ...). satp directly includes cryptography and
##  message authentication based on the methods used by SRTP.  It is
##  intended to deliver a generic, scaleable and secure solution for
##  tunneling and relaying of packets of any protocol.
##
##
##  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
##  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
##
##  In addition, as a special exception, the copyright holders give
##  permission to link the code of portions of this program with the
##  OpenSSL library under certain conditions as described in each
##  individual source file, and distribute linked combinations
##  including the two.
##  You must obey the GNU General Public License in all respects
##  for all of the code used other than OpenSSL.  If you modify
##  file(s) with this exception, you may extend this exception to your
##  version of the file(s), but you are not obligated to do so.  If you
##  do not wish to do so, delete this exception statement from your
##  version.  If you delete this exception statement from all source
##  files in the program, then also delete it here.
##

VERSION=$(shell cat ../version)

MANPAGES := anytun.8 anytun-controld.8 anytun-config.8 anytun-showtables.8 #anyrtpproxy.8
XML := $(MANPAGES:%.8=%.8.xml)

.PHONY: clean realclean

all: manpage

define create-manpage
	a2x -f manpage $(1)
	@ sed -i -e 's/\[FIXME: source\]/anytun ${VERSION}/' $(2)
	@ sed -i -e 's/\[FIXME: manual\]/$(2:.8=) user manual/' $(2)
	@ sed -i -e 's/^\($(subst -,\\-,$(2:.8=))\)$$/\\fB\1\\fR/' $(2)
	@ sed -i -e 's/^  \[ \([^ ]*\)/  [ \\fB\1\\fR/' $(2)
endef

%.8: %.8.txt
	$(call create-manpage,$<,$@)

manpage: $(MANPAGES)

clean:
	rm -f $(XML)

realclean:
	rm -f $(MANPAGES)
