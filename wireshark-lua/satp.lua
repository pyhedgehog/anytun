--  anytun
--
--  The secure anycast tunneling protocol (satp) defines a protocol used
--  for communication between any combination of unicast and anycast
--  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
--  mode and allows tunneling of every ETHER TYPE protocol (e.g.
--  ethernet, ip, arp ...). satp directly includes cryptography and
--  message authentication based on the methodes used by SRTP.  It is
--  intended to deliver a generic, scaleable and secure solution for
--  tunneling and relaying of packets of any protocol.
--
--
--  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
--                          Christian Pointner <satp@wirdorange.org>
--
--  This file is part of Anytun.
--
--  Anytun is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  any later version.
--
--  Anytun is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with anytun.  If not, see <http://www.gnu.org/licenses/>.


do
 local proto_satp = Proto("SATP","Secure Anycast Tunneling Protocol")

 local payload_types = {
       [0x0800] = "IPv4",
       [0x6558] = "Ethernet",
       [0x86DD] = "IPv6"
 }

 local payload_dissector = {
       [0x0800] = "ip",
       [0x6558] = "eth",
       [0x86DD] = "ipv6"
 }

 local field_seq = ProtoField.uint32("satp.seq","Sequence Number",base.DEC)
 local field_sid = ProtoField.uint16("satp.sid","Sender ID",base.DEC)
 local field_mux = ProtoField.uint16("satp.mux","Mux",base.DEC)
 local field_ptype = ProtoField.uint16("satp.ptype","Payload Type (plain?)",base.HEX,payload_types)

 proto_satp.fields = { field_seq, field_sid, field_mux, field_ptype }


 -- create a function to dissect it
 function proto_satp.dissector(buffer,pinfo,tree)
    local info_string = "Sender Id: " .. buffer(4,2):uint() .. ", Mux: " .. buffer(6,2):uint() .. ", SeqNr: " .. buffer(0,4):uint()
    pinfo.cols.protocol = "SATP"
    pinfo.cols.info = info_string

    local subtree = tree:add(proto_satp,buffer(),"SATP, " .. info_string)

    subtree:add(field_seq, buffer(0,4))
    subtree:add(field_sid, buffer(4,2))
    subtree:add(field_mux, buffer(6,2))

    local payload_type = buffer(8,2):uint()

    if payload_dissector[payload_type] ~= nil then
       subtree:add(field_ptype, buffer(8,2))
       Dissector.get(payload_dissector[payload_type]):call(buffer(10):tvb(),pinfo,tree)
    else
       Dissector.get("data"):call(buffer(8):tvb(),pinfo,tree)
    end
 end

 -- load the udp.port table

 udp_table = DissectorTable.get("udp.port")
 
 -- register our protocol to handle udp port 4444
 udp_table:add(4444,proto_satp)
end
