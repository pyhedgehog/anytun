do
 -- satp example
 -- declare our protocol
 
 satp_proto = Proto("SATP","Secure Anycast Tunneling Protocol")

 -- create a function to dissect it
 function satp_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "SATP"

    local subtree = tree:add(satp_proto,buffer(),"SATP, Sender Id: " .. buffer(4,2):uint() .. ", Mux: " .. buffer(6,2):uint() .. ", SeqNr: " .. buffer(0,4):uint())

    subtree:add(buffer(0,4),"Sequence Number: " .. buffer(0,4):uint())
    subtree:add(buffer(4,2),"Sender ID: " .. buffer(4,2):uint())
    subtree:add(buffer(6,2),"Mux: " .. buffer(6,2):uint())
    subtree:add(buffer(8,2),"Payload Type: " .. buffer(8,2):uint())

    local data_dis = Dissector.get("data")
    local payload_dis = Dissector.get("ip")
    
    if payload_dis ~= nil then
      payload_dis:call(buffer(10):tvb(),pinfo,tree)
    else
      data_dis:call(buffer(10):tvb(),pinfo,tree)
    end
 end

 -- load the udp.port table

 udp_table = DissectorTable.get("udp.port")
 
 -- register our protocol to handle udp port 4444
 udp_table:add(4444,satp_proto)
end
