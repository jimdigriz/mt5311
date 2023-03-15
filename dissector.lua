-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for I2C wrapped in HDLC or something. So you ask for a
-- register and it returns its value as 3 octets.
--
-- Everything is guess work, so errors are guarenteed!
--
-- Assumptions are codified with expert.group.ASSUMPTION

local vs_register = {}
function read_register_map ()
	local status

	local line_count = 0
	local warn = function (msg)
		print("mt5311 dissector.lua: line " .. tostring(line_count) .. " " .. msg)
	end
	for line in io.lines("register.map") do
		line_count = line_count + 1

		line = line:gsub("#.*$", "")
		line = line:gsub("^%s+", ""):gsub("%s+$", "")

		local r = {}
		if #line > 0 then
			for v in (line .. "\t"):gmatch("[^\t]*\t") do
				r[#r + 1] = v:sub(1, -2)
			end
		end

		if #r == 1 or #r == 2 then
			status, r[1] = pcall(function () return tonumber(r[1]) end)
			if status then
				if #r == 2 then
					vs_register[r[1]] = r[2]
				end
			else
				warn("unparsable register value in register.map, ignoring")
			end
		elseif #r ~= 0 then
				warn("unparsable in register.map, ignoring")
		end
	end
end
read_register_map()

local vs_status = {
	[0] = "Success",
	[255] = "No error"
}

local CMD = {
	["read_reg"]	= 1
}
local vs_cmd = {
	[1]		= "Read Register"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

proto.fields.hdr = ProtoField.bytes("ebm.hdr", "Header")
proto.fields.flags = ProtoField.bytes("ebm.flags", "Flags")
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
proto.fields.padding = ProtoField.bytes("ebm.padding", "Padding")

proto.experts.assert = ProtoExpert.new("ebm.assert", "Protocol", expert.group.ASSUMPTION, expert.severity.WARN)

local f_code = Field.new("ebm.code")
local f_seq = Field.new("ebm.seq")
local f_cmd_read_reg = Field.new("ebm.cmd.read_reg")

-- conversation tracking for populating
-- frametype and reconciling reads with data
local requests

function proto.init ()
	-- FIXME: not sure this is safe over multiple sessions
	requests = {}
end

function proto.dissector (tvb, pinfo, tree)
	local len = tvb:len()

	pinfo.cols.info = proto.description
	pinfo.cols.protocol = proto.name

	local ebm_tree = tree:add(proto, tvb())

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
	local hdr_tree = ebm_tree:add(proto.fields.hdr, hdr_tvb())

	local hdr_flags_tvb = hdr_tvb(0, 3)
	local hdr_flags = hdr_tree:add(proto.fields.flags, hdr_flags_tvb())
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
		if not requests[seq] then requests[seq] = { ["cmds"] = {} } end
		requests[seq][response] = pinfo.number
	end

	hdr_tree:add(proto.fields.status, hdr_tvb(7, 1))
	local hdr_status_tvb = hdr_tvb(7, 1)
	if not ((response and hdr_status_tvb:uint() == 0x00) or (not response and hdr_status_tvb:uint() == 0xff)) then
		hdr_tree:add_proto_expert_info(proto.experts.assert, "Status has unexpected value")
	end

	local payload_tvb = tvb(8)
	local payload_tree = ebm_tree:add(proto, payload_tvb(), "Payload")

	local pi, pi_tvb
	local offset = 0
	if response then
		--  0                   1                   2
		--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |                     Data                      |
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		local cmds = requests[seq]["cmds"]
		for i, cmd in pairs(cmds) do
			pi_tvb = payload_tvb(offset, math.min(3, payload_tvb:len() - offset))
			pi = payload_tree:add(proto.fields.data, pi_tvb())
			offset = offset + pi_tvb:len()

			if pi_tvb:len() < 3 then
				payload_tvb:add_proto_expert_info(proto.experts.assert, "Truncated Response")
				break
			end

			if pinfo.visited then
				if cmd[1] == CMD.read_reg then
					local regname = vs_register[cmd[2]] or "Unknown"
					pi:append_text(" (Read Register: " .. regname .. " [0x" .. string.format("%x", cmd[2]) .. "])")
				end
			end
		end
	else
		while payload_tvb:len() > offset do
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
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd, pi_tvb(0, 1))
				if pi_tvb(1, 1):uint() ~= 0 then
					pi:add_proto_expert_info(proto.experts.assert, "Flags not all unset")
				end
				pi:add(proto.fields.cmd_read_reg, pi_tvb(2, 2))
				pi:add(proto.fields.cmd_read_len, pi_tvb(4, 2))
				if pi_tvb(4, 2):uint() ~= 3 then
					pi:add_proto_expert_info(proto.experts.assert, "Register Length expected to be 3")
				end

				local cmd_read_reg = f_cmd_read_reg()()
				if not pinfo.visited then
					table.insert(requests[seq]["cmds"], { CMD.read_reg, cmd_read_reg })
				end
			else
				pi = payload_tree:add(proto, payload_tvb(offset), "Unknown")
				offset = payload_tvb:len()

				pi:add_proto_expert_info(proto.experts.assert, "Unknown Command")

				if not pinfo.visited then
					table.insert(requests[seq]["cmds"], { nil })
				end
			end
		end
	end

	if payload_tvb:len() > offset then
		local padding_tvb = payload_tvb(offset)
		local padding_tree = payload_tree:add(proto.fields.padding, padding_tvb())
		for i=1, padding_tvb:len() - 1 do
			if padding_tvb(i, 1):uint() ~= 0 then
				padding_tree:add_proto_expert_info(proto.experts.assert, "Padding has non-zero bytes")
				break
			end
		end
	end

	return len
end

DissectorTable.get("ethertype"):add(0x6120, proto)
