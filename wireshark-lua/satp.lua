do
 -- satp example
 -- declare our protocol
 
 local proto_satp = Proto("SATP","Secure Anycast Tunneling Protocol")

 local payload_types = {
       [0x0800] = "IPv4",
       [0x6558] = "Ethernet",
       [0x56DD] = "IPv6"
 }

 local payload_dissector = {
       [0x0800] = "ip",
       [0x6558] = "ethernet",
       [0x56DD] = "ipv6"
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
