local my_proto = Proto("myproto", "My Custom Protocol")
my_proto.prefs.enabled = Pref.bool("Enable My Custom Protocol", true, "Enable or disable the protocol dissector")

local f = my_proto.fields
f.message_type = ProtoField.uint8("myproto.message_type", "Message Type", base.DEC)
f.message_id = ProtoField.uint16("myproto.message_id", "Message ID", base.DEC)
f.fragment_number = ProtoField.uint16("myproto.fragment_number", "Fragment Number", base.DEC)
f.total_fragments = ProtoField.uint16("myproto.total_fragments", "Total Fragments", base.DEC)
f.crc = ProtoField.uint16("myproto.crc", "CRC", base.HEX)
f.payload = ProtoField.bytes("myproto.payload", "Payload Data")

function my_proto.dissector(buffer, pinfo, tree)
    if not my_proto.prefs.enabled then
        return
    end

    pinfo.cols.protocol = my_proto.name

    local subtree = tree:add(my_proto, buffer(), "My Custom Protocol Data")

    if buffer:len() < 9 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short")
        return
    end

    local offset = 0
    local message_type = buffer(offset, 1):uint()
    subtree:add(f.message_type, buffer(offset, 1))
    offset = offset + 1

    subtree:add(f.message_id, buffer(offset, 2))
    offset = offset + 2

    subtree:add(f.fragment_number, buffer(offset, 2))
    offset = offset + 2

    subtree:add(f.total_fragments, buffer(offset, 2))
    offset = offset + 2

    subtree:add(f.crc, buffer(offset, 2))
    offset = offset + 2

    if buffer:len() > offset then
        subtree:add(f.payload, buffer(offset))
    end

    if message_type == 1 then
        pinfo.cols.info:set("SYN")
    elseif message_type == 2 then
        pinfo.cols.info:set("SYN_ACK")
    elseif message_type == 3 then
        pinfo.cols.info:set("ACK")
    elseif message_type == 4 then
        pinfo.cols.info:set("DATA")
    elseif message_type == 5 then
        pinfo.cols.info:set("ACK_DATA")
    elseif message_type == 6 then
        pinfo.cols.info:set("NACK_DATA")
    elseif message_type == 7 then
        pinfo.cols.info:set("HEARTBEAT")
    elseif message_type == 8 then
        pinfo.cols.info:set("HEARTBEAT_ACK")
    elseif message_type == 9 then
        pinfo.cols.info:set("FILE_INFO")
    else
        pinfo.cols.info:set("UNKNOWN")
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(54321, my_proto)
