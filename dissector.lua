-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for I2C or something. So you ask for an address and it
-- returns 3 bytes that correspond to an address slot.
--
-- Everything is guess work, so errors are guarenteed!

local registers = {
	[0x6f2f] = "Electrical Length",					-- "\0\0\xb9" = 185m
	[0x7d90] = "Carrier Set",					-- "\0\0\x03" = 3
	[0x7eac] = "VCXO (Voltage Controlled Crystal Oscillator?)",	-- "\x4c\xa0\0" = 0x4ca000

	-- Far End
	[0x79ce] = "Inventory Version [ 0 -  2]",			-- "v12"
	[0x79cf] = "Inventory Version [ 3 -  5]",			-- ".00"
	[0x79d0] = "Inventory Version [ 6 -  8]",			-- ".28"
	[0x79d1] = "Inventory Version [ 9 - 11]",			-- "   "
	[0x79d2] = "Inventory Version [12 - 14]",			-- "   "
	[0x79d3] = "Inventory Version [15 - 17]",			-- "\0\0\0"
	[0x7d98] = "Peer Vendor ID [2,0,1]",				-- "CBD"
	[0x7d99] = "Peer Vendor ID [SI1,SI0,3]",			-- "\xC1\xC0" .. "M"
--	[0x7d99] = "Peer Vendor Specific Information [1,0,_]",		-- "\xC1\xC0" .. "M"
	[0x7ea4] = "MAC Address [ 0 - 2]",				-- "\0\0\0"
	[0x7ea5] = "MAC Address [ 3 - 5]",				-- "\0\0\0"
	[0x7ea6] = "MAC Address [ 6 - 8]",				-- "\0\0\0"
	[0x7ea7] = "MAC Address [ 9 -11]",				-- "\0\0\0"

	-- Near End
	[0x79e4] = "Peer Vendor ID [_,_,0]",				-- "\0\0M",
	[0x79e5] = "Peer Vendor ID [1-3]",				-- "ETA",
	[0x79ea] = "Inventory Version [ 0 -  2]",			-- "1_6"
	[0x79eb] = "Inventory Version [ 3 -  5]",			-- "0_8"
	[0x79ec] = "Inventory Version [ 6 -  8]",			-- "255"
	[0x79ed] = "Inventory Version [ 9 - 11]",			-- " MT"
	[0x79ee] = "Inventory Version [12 - 14]",			-- "531"
	[0x79ef] = "Inventory Version [15 - 17]",			-- "1\0\0"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

local pf_hdr = ProtoField.bytes("ebm.flags")
table.insert(proto.fields, pf_hdr)

local pf_code = ProtoField.bool("ebm.flags.code", "Response", 8, { "this is a response", "this is a request" }, 0x80)
table.insert(proto.fields, pf_code)
local f_code = Field.new("ebm.flags.code")

local pf_seq = ProtoField.uint32("ebm.seq", "Sequence Number")
table.insert(proto.fields, pf_seq)

local pf_unknown = ProtoField.uint8("ebm.unknown", "Unknown")
table.insert(proto.fields, pf_unknown)

local pf_addr = ProtoField.uint16("ebm.addr", "Address", base.HEX)
table.insert(proto.fields, pf_addr)

local pf_addr_width = ProtoField.uint16("ebm.addr_width", "Address Width")
table.insert(proto.fields, pf_addr_width)

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
	-- |             ?????             |     Flags     |    Sequence   :
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- :                           Sequence                            |
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |    Unknown    |            Payload
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	-- Flags
	--
	--        0 1 2 3 4 5 6 7
	--       +-+-+-+-+-+-+-+-+
	--       |C 0 0 0 0 0 0 1|
	--       +-+-+-+-+-+-+-+-+
	--
	--    C  Code field
	--
	--       0 Request
	--
	--       1 Response
	--
	-- Unknown
	--
	--    When C = 0 (Request)

	local hdr_tvb = tvb(0, 8)
	local hdr = subtree:add(proto, hdr_tvb(), "Header")

	local hdr_flags_tvb = hdr_tvb(0, 3)
	local hdr_flags = hdr:add(proto, hdr_flags_tvb(), "Flags")
	hdr_flags:add(pf_code, hdr_flags_tvb(2, 1))

	local response = f_code()()

	if bit.band(hdr_flags_tvb:uint(2, 1), 0xff - 0x80 - 0x01) ~= 0 then
		hdr_flags:add_proto_expert_info(ef_assert, "Flags bits 1-6 not all unset")
	end
	if bit.band(hdr_flags_tvb:uint(2, 1), 0x01) ~= 1 then
		hdr_flags:add_proto_expert_info(ef_assert, "Flags bit 7 not set")
	end

	hdr:add(pf_seq, hdr_tvb(3, 4))
	hdr:add(pf_unknown, hdr_tvb(7, 1))
	local hdr_unknown_tvb = hdr_tvb(7, 1)
	if not ((response and hdr_unknown_tvb:uint() == 0x00) or (not response and hdr_unknown_tvb:uint() == 0xff)) then
		hdr_flags:add_proto_expert_info(ef_assert, "Unknown has unexpected value")
	end

	local payload_tvb = tvb(8)
	local payload = subtree:add(proto, payload_tvb(), "Payload")

	if response then
		payload:add(pf_data, payload_tvb(0, 3))
		payload:add(pf_padding, payload_tvb(3))
	else
		payload:add(pf_addr, payload_tvb(2, 2))
		payload:add(pf_addr_width, payload_tvb(4, 2))
		payload:add(pf_padding, payload_tvb(6))
	end

	pinfo.cols.info:append(response and ": Response" or ": Query")

	return len
end

local dissector = DissectorTable.get("ethertype")
dissector:add(0x6120, proto)
