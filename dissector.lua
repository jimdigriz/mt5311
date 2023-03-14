-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for HDLC/I2C or something. So you ask for a register and
-- it returns its value as 3 octets.
--
-- Everything is guess work, so errors are guarenteed!

local vs_register = {
	-- System Table


--	[0x001e] = "",						-- "\x40\x00\x02"

	[0x6c31] = "Firmware Version",				-- "\x75\x02\x02" = 750202
	[0x6c32] = "Firmware Date (DDMMYY)",			-- "\x09\x07\x18" = 090718 (might be US format!)
	[0x6c33] = "Firmware Time (HHMMSS)",			-- "\x17\x30\x44" = 173044
--	[0x6c34] = "",						-- "\x80\x15\x68"
--	[0x6c35] = "",						-- "\x00\x03\x29"
--	[0x6c36] = "",						-- "\x47\x41\x54"
	[0x6f00] = "Bootcode Version",				-- "\xff\x00\x03" = ff0003
	[0x6f2f] = "Electrical Length",				-- "\x00\x00\xb9" = 185m
	[0x7d90] = "Carrier Set",				-- "\x00\x00\x03" = 3

	-- Far End
	[0x79ce] = "Inventory Version [0:2]",			-- "v12"
	[0x79cf] = "Inventory Version [3:5]",			-- ".00"
	[0x79d0] = "Inventory Version [6:8]",			-- ".28"
	[0x79d1] = "Inventory Version [9:11]",			-- "   "
	[0x79d2] = "Inventory Version [12:14]",			-- "   "
	[0x79d3] = "Inventory Version [15:17]",			-- "\0\0\0"
	[0x7d98] = "Peer Vendor ID [2,0,1]",			-- "CBD"
	[0x7d99] = "Peer Vendor ID (and SpecInfo) [SI1,SI0,3]",	-- "\xC1\xC0" .. "M"
--	[0x7d99] = "Peer Vendor Specific Information [1,0,_]",	-- "\xC1\xC0" .. "M"
	[0x7ea4] = "MAC Address [0:2]",				-- "\0\0\0"
	[0x7ea5] = "MAC Address [3:5]",				-- "\0\0\0"
	[0x7ea6] = "MAC Address [6:8]",				-- "\0\0\0"
	[0x7ea7] = "MAC Address [9:11]",			-- "\0\0\0"

	-- Near End
	[0x79e4] = "Peer Vendor ID [_,_,0]",			-- "\0\0M",
	[0x79e5] = "Peer Vendor ID [1:3]",			-- "ETA",
	[0x79ea] = "Inventory Version [0:2]",			-- "1_6"
	[0x79eb] = "Inventory Version [3:5]",			-- "0_8"
	[0x79ec] = "Inventory Version [6:8]",			-- "255"
	[0x79ed] = "Inventory Version [9:11]",			-- " MT"
	[0x79ee] = "Inventory Version [12:14]",			-- "531"
	[0x79ef] = "Inventory Version [15:17]",			-- "1\0\0"
	[0x7eac] = "VCXO (Voltage Controlled Crystal Oscillator?)",	-- "\x4c\xa0\0" = 0x4ca000
}

local vs_status = {
	[0] = "Success",
	[255] = "No error"
}

local vs_cmd = {
	[1] = "Read Register"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

proto.fields.hdr = ProtoField.bytes("ebm.flags")
proto.fields.code = ProtoField.bool("ebm.code", "Response", 8, { "this is a response", "this is a request" }, 0x80)
proto.fields.seq = ProtoField.uint32("ebm.seq", "Sequence Number")
proto.fields.frame_request = ProtoField.framenum("ebm.request", "Request In", nil, frametype.REQUEST)
proto.fields.frame_response = ProtoField.framenum("ebm.response", "Response In", nil, frametype.RESPONSE)
proto.fields.status = ProtoField.uint8("ebm.status", "Status", nil, vs_status)

proto.fields.cmd = ProtoField.uint8("ebm.cmd", "Type", nil, vs_cmd)
--
proto.fields.cmd_read_reg = ProtoField.uint16("ebm.cmd.read_reg", "Address", base.HEX, vs_register)
proto.fields.cmd_read_len = ProtoField.uint16("ebm.cmd.read_len", "Length")
--
proto.fields.data = ProtoField.bytes("ebm.data", "Data")

proto.experts.assert = ProtoExpert.new("ebm.assert", "Protocol", expert.group.ASSUMPTION, expert.severity.WARN)

local f_code = Field.new("ebm.code")
local f_seq = Field.new("ebm.seq")

-- conversation tracking for populating
-- frametype and reconciling reads with data
local requests

-- FIXME: not sure this is safe over multiple sessions
function proto.init ()
	requests = {}
end

function proto.dissector (tvb, pinfo, tree)
	local len = tvb:len()

	pinfo.cols.info = proto.description
	pinfo.cols.protocol = proto.name

	local ebm_tree = tree:add(proto, tvb(), "EBM Protocol")

	--  0                   1                   2                   3
	--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |                     Flags                     |    Sequence   :
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- :                   Sequence                    |     Status    |
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |            Payload
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	-- Flags
	--        0                   1                   2
	--        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
	--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--       |0 0 0 0 0 0 0 0 0 0 0 0 B A A B B 0 0 0 0 0 0 1|
	--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	--    A
	--
	--        0 - Response
	--
	--        1 - Request
	--
	--    B
	--
	--        0 - Request
	--
	--        1 - Response
	--
	-- Status
	--
	--    0 - Success
	--
	--  255 - Not applicable

	local hdr_tvb = tvb(0, 8)
	local hdr_tree = ebm_tree:add(proto, hdr_tvb(), "Header")

	local hdr_flags_tvb = hdr_tvb(0, 3)
	local hdr_flags = hdr_tree:add(proto, hdr_flags_tvb(), "Flags")
	hdr_flags:add(proto.fields.code, hdr_flags_tvb(2, 1))	-- bit 16

	local response = f_code()()

	pinfo.cols.info:append(response and ": Response" or ": Query")
	if bit.band(hdr_flags_tvb(0, 2):uint(), 0xfff0) ~= 0 then
		hdr_flags:add_proto_expert_info(proto.experts.assert, "Flags bits 1-11 not all unset")
	end
	if response then
		if bit.band(hdr_flags_tvb(1, 1):uint(), 0x0f) ~= 9 then
			hdr_flags:add_proto_expert_info(proto.experts.assert, "Flags bits 12-15 not 0b1001")
		end
	else
		if bit.band(hdr_flags_tvb(1, 1):uint(), 0x0f) ~= 6 then
			hdr_flags:add_proto_expert_info(proto.experts.assert, "Flags bits 12-15 not 0b0110")
		end
	end
	if bit.band(hdr_flags_tvb(2, 1):uint(), 0x7e) ~= 0 then
		hdr_flags:add_proto_expert_info(proto.experts.assert, "Flags bits 17-22 not all unset")
	end
	if bit.band(hdr_flags_tvb(2, 1):uint(), 0x01) ~= 1 then
		hdr_flags:add_proto_expert_info(proto.experts.assert, "Flags bits 23 not set")
	end

	hdr_tree:add(proto.fields.seq, hdr_tvb(3, 4))
	local seq = f_seq()()
	if pinfo.visited then
		hdr_tree:add(proto.fields[response and "frame_request" or "frame_response"], requests[seq][not response]):set_generated()
	else
		if not requests[seq] then requests[seq] = {} end
		requests[seq][response] = pinfo.number
	end

	hdr_tree:add(proto.fields.status, hdr_tvb(7, 1))
	local hdr_status_tvb = hdr_tvb(7, 1)
	if not ((response and hdr_status_tvb:uint() == 0x00) or (not response and hdr_status_tvb:uint() == 0xff)) then
		hdr_tree:add_proto_expert_info(proto.experts.assert, "Status has unexpected value")
	end

	local payload_tvb = tvb(8)
	local payload_tree = ebm_tree:add(proto, payload_tvb(), "Payload")

	local pi
	local pi_tvb
	local offset = 0
	while payload_tvb:len() > offset do
		if response then
--			if type == 0 then	-- Data (Type = 0)
			if payload_tvb:len() >= offset + 3 then
				--  0                   1                   2
				--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |                     Data                      |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				pi_tvb = payload_tvb(offset, 3)
				pi = payload_tree:add(proto, pi_tvb(), "Data")
				offset = offset + 3
			else
				pi = payload_tree:add(proto, payload_tvb(offset), "Unknown")
				offset = payload_tvb:len()

				pi:add_proto_expert_info(proto.experts.assert, "Unknown Response")
			end
		else
			local type = payload_tvb(offset, 1):uint()

			if type == 0 then
				break
			elseif type == 1 then	-- Read Register (Type = 1)
				--  0                   1                   2                   3
				--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |     Type      |0 0 0 0 0 0 0 0|            Register           :
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |        Register Length        |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				pi_tvb = payload_tvb(offset, 6)
				pi = payload_tree:add(proto, pi_tvb(), "Read Register")
				offset = offset + 6

				pi:add(proto.fields.cmd, pi_tvb(0, 1))
				if pi_tvb(1, 1):uint() ~= 0 then
					pi:add_proto_expert_info(proto.experts.assert, "Flags not all unset")
				end
				pi:add(proto.fields.cmd_read_reg, pi_tvb(2, 2))
				pi:add(proto.fields.cmd_read_len, pi_tvb(4, 2))
				if pi_tvb(4, 2):uint() ~= 3 then
					pi:add_proto_expert_info(proto.experts.assert, "Register Length expected to be 3")
				end
			else
				pi = payload_tree:add(proto, payload_tvb(offset), "Unknown")
				offset = payload_tvb:len()

				pi:add_proto_expert_info(proto.experts.assert, "Unknown Command")
			end
		end
	end

	return len - (payload_tvb:len() - offset)
end

local dissector = DissectorTable.get("ethertype")
dissector:add(0x6120, proto)
