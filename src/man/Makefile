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

all: manpage

anytun.8: anytun.8.txt
	a2x -f manpage anytun.8.txt

anytun-controld.8: anytun-controld.8.txt
	a2x -f manpage anytun-controld.8.txt

anytun-config.8: anytun-config.8.txt
	a2x -f manpage anytun-config.8.txt

anytun-showtables.8: anytun-showtables.8.txt
	a2x -f manpage anytun-showtables.8.txt

anyrtpproxy.8: anyrtpproxy.8.txt
	a2x -f manpage anyrtpproxy.8.txt


manpage: anytun.8 anytun-controld.8 anytun-config.8 anytun-showtables.8 anyrtpproxy.8

clean:
	rm -f anytun.8 anytun.8.xml
	rm -f anytun-controld.8 anytun-controld.8.xml
	rm -f anytun-config.8 anytun-config.8.xml
	rm -f anytun-showtables.8 anytun-showtables.8.xml
	rm -f anyrtpproxy.8 anyrtpproxy.8.xml