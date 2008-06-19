/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "connectionParam.h"

//ConnectionParam::ConnectionParam():kd_(*(new KeyDerivation)),seq_window_(*(new SeqWindow(0))),seq_nr_(0),remote_host_(""),remote_port_(0)
//{
//}

ConnectionParam::ConnectionParam(KeyDerivation& kd, SeqWindow& seq_window,seq_nr_t seq_nr, std::string remote_host, u_int16_t remote_port) : kd_(kd),seq_window_(seq_window),seq_nr_(seq_nr),remote_host_(remote_host), remote_port_(remote_port)
{
}

ConnectionParam::ConnectionParam(const ConnectionParam & src) : kd_(src.kd_),seq_window_(src.seq_window_),seq_nr_(src.seq_nr_),remote_host_(src.remote_host_), remote_port_(src.remote_port_),mutex_()
{
}
