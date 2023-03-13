-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for HDLC/I2C or something. So you ask for a register and
-- it returns its value as 3 octets.
--
-- Everything is guess work, so errors are guarenteed!

local vs_register = {
--	[0x001e] = "",						-- "\x40\x00\x02"

	[0x6c31] = "Firmware Version",				-- "\x75\x02\x02" = 750202
	[0x6c32] = "Firmware Date (DDMMYY)",			-- "\x09\x07\x18" = 090718 (might be US format!)
	[0x6c33] = "Firmware Time (HHMMSS)",			-- "\x17\x30\x44" = 173044
--	[0x6c34] = "",						-- "\x80\x15\x68"
--	[0x6c35] = "",						-- "\x00\x03\x29"
--	[0x6c36] = "",						-- "\x47\x41\x54"
	[0x6f2f] = "Electrical Length",				-- "\0\0\xb9" = 185m
	[0x7d90] = "Carrier Set",				-- "\0\0\x03" = 3

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

local vs_request_payload_type = {
	[0] = "Request"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

local pf_hdr = ProtoField.bytes("ebm.flags")
table.insert(proto.fields, pf_hdr)

local pf_code = ProtoField.bool("ebm.flags.code", "Response", 8, { "this is a response", "this is a request" }, 0x80)
table.insert(proto.fields, pf_code)
local f_code = Field.new("ebm.flags.code")

local pf_seq = ProtoField.uint32("ebm.seq", "Sequence Number")
table.insert(proto.fields, pf_seq)

local pf_status = ProtoField.uint8("ebm.status", "Status", nil, vs_status)
table.insert(proto.fields, pf_status)

local pf_type = ProtoField.uint8("ebm.type", "Type", nil, vs_request_payload_type)
table.insert(proto.fields, pf_type)

local pf_reg = ProtoField.uint16("ebm.reg", "Register", base.HEX, vs_register)
table.insert(proto.fields, pf_reg)

local pf_regsize = ProtoField.uint16("ebm.regsize", "Register Size")
table.insert(proto.fields, pf_regsize)

local pf_data = ProtoField.bytes("ebm.data", "Data")
table.insert(proto.fields, pf_data)

local pf_padding = ProtoField.bytes("ebm.padding", "Padding")
table.insert(proto.fields, pf_padding)

local ef_assert = ProtoExpert.new("ebm.assert", "Protocol", expert.group.ASSUMPTION, expert.severity.WARN)
table.insert(proto.experts, ef_assert)

function proto.dissector (tvb, pinfo, tree)
	local len = tvb:len()
	-- 50: request, 46: code
	if not (len == 50 or len == 46) then return end

	pinfo.cols.info = proto.description
	pinfo.cols.protocol = proto.name

	local subtree = tree:add(proto, tvb(), "EBM Protocol")

	--  0                   1                   2                   3
	--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |                     Flags                     |    Sequence   :
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- :                           Sequence                            |
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |     Status    |            Payload
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	-- Code (C) field
	--
	--    0 - Request
	--
	--    1 - Response
	--
	-- Status
	--
	--    0 - Success
	--
	--  255 - Not applicable

	local hdr_tvb = tvb(0, 8)
	local hdr = subtree:add(proto, hdr_tvb(), "Header")

	local hdr_flags_tvb = hdr_tvb(0, 3)
	local hdr_flags = hdr:add(proto, hdr_flags_tvb(), "Flags")
	hdr_flags:add(pf_code, hdr_flags_tvb(2, 1))

	local response = f_code()()

	pinfo.cols.info:append(response and ": Response" or ": Query")

	if bit.band(hdr_flags_tvb:uint(2, 1), 0xff - 0x80 - 0x01) ~= 0 then
		hdr_flags:add_proto_expert_info(ef_assert, "Flags bits 1-6 not all unset")
	end
	if bit.band(hdr_flags_tvb:uint(2, 1), 0x01) ~= 1 then
		hdr_flags:add_proto_expert_info(ef_assert, "Flags bit 7 not set")
	end

	hdr:add(pf_seq, hdr_tvb(3, 4))
	hdr:add(pf_status, hdr_tvb(7, 1))
	local hdr_status_tvb = hdr_tvb(7, 1)
	if not ((response and hdr_status_tvb:uint() == 0x00) or (not response and hdr_status_tvb:uint() == 0xff)) then
		hdr:add_proto_expert_info(ef_assert, "Status has unexpected value")
	end

	local payload_tvb = tvb(8)
	local payload = subtree:add(proto, payload_tvb(), "Payload")

	local padding_tvb
	if response then
		-- Response (C = 1)
		--
		--  0                   1                   2                   3
		--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |                    Data                       |    Padding    :
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- :            Padding
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--
		-- Data
		--
		--    Three (3) octets of data
		--
		-- Padding
		--
		--    35 octets zeroed out

		payload:add(pf_data, payload_tvb(0, 3))
		padding_tvb  = payload_tvb(3)
		if padding_tvb:len() ~= 35 then
			payload:add_proto_expert_info(ef_assert, "Padding expected to be 35 octets")
		end
	else
		-- Request (C = 0)
		--
		--  0                   1                   2                   3
		--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |     Flags     |     Type      |             Address           |
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |        Address Width          |             Padding           :
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- :            Padding
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--
		-- Flags
		--
		--        0 1 2 3 4 5 6 7
		--       +-+-+-+-+-+-+-+-+
		--       |0 0 0 0 0 0 0 H|
		--       +-+-+-+-+-+-+-+-+
		--
		--    H  MUST be set
		--
		-- Type
		--
		--    0 - octets
		--
		-- Register
		--
		--    Unsigned 16-bit integer providing the register number to read
		--
		-- Register Width
		--
		--    Unsigned 16-bit integer providing the number of octets to return.
		--    The value MUST be three (3).
		--
		-- Padding
		--
		--    36 octets zeroed out

		if bit.band(payload_tvb(0, 1):uint(), 0x01) ~= 1 then
			payload:add_proto_expert_info(ef_assert, "Request Flags bit 7 not set")
		end

		payload:add(pf_type, payload_tvb(1, 1))
		payload:add(pf_reg, payload_tvb(2, 2))
		payload:add(pf_regsize, payload_tvb(4, 2))
		if payload_tvb(4, 2):uint() ~= 3 then
			payload:add_proto_expert_info(ef_assert, "Register Size expected to be 3")
		end
		padding_tvb  = payload_tvb(6)
		if padding_tvb:len() ~= 36 then
			payload:add_proto_expert_info(ef_assert, "Padding expected to be 36 octets")
		end
	end

	payload:add(pf_padding, padding_tvb())
	for i=0,padding_tvb:len() - 1 do
		if padding_tvb(i, 1):uint() ~= 0x00 then
			payload:add_proto_expert_info(ef_assert, "Padding has non-zero bytes")
			break
		end
	end

	return len
end

local dissector = DissectorTable.get("ethertype")
dissector:add(0x6120, proto)
