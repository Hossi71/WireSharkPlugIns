ap_discover_proto = Proto("JWF-SQL-SRVC", "JWF-SQL-Service Protocol")

cmd = ProtoField.int16("JWF-SQL-SRVC.version", "cmd", base.DEC)
src_addr = ProtoField.ipv4("JWF-SQL-SRVC.version", "src_addr", base.HEX)
dest_addr = ProtoField.ipv4("JWF-SQL-SRVC.version", "dest_addr", base.HEX)
version = ProtoField.string("JWF-SQL-SRVC.version", "version", base.Unicode)

ap_discover_proto.fields = { cmd }
ap_discover_proto.fields = { src_addr }
ap_discover_proto.fields = { dest_addr }
ap_discover_proto.fields = { version }

function ap_discover_proto.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

	if length == 364 then
		pinfo.cols.protocol = ap_discover_proto.name

		local subtree = tree:add(ap_discover_proto, buffer(), "JWF Discovery Message typ 1")

		subtree:add_le(cmd, buffer(0,2))	
		subtree:add_le(src_addr, buffer(2,4))	
		subtree:add_le(dest_addr, buffer(6,4))
		subtree:add_le(version, buffer(5,5))
	else
		pinfo.cols.protocol = ap_discover_proto.name

		local subtree = tree:add(ap_discover_proto, buffer(), "JWF Discovery Message typ 2")

		subtree:add_le(cmd, buffer(0,2))	
		subtree:add_le(src_addr, buffer(2,4))	
		subtree:add_le(dest_addr, buffer(6,4))
		subtree:add_le(version, buffer(5,5))
	
	end
end

local tcp_port = DissectorTable.get("udp.port")
tcp_port:add(10001, ap_discover_proto)