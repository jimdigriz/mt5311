-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for I2C. You ask for a register and it returns its value.
--
-- Everything is guess work, so errors are guarenteed!
--
-- Assumptions are codified with expert.group.ASSUMPTION

local vs_mode = {
	[1]	= "Query"
}

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
local vs_cmd_type = {
	[1]		= "Read Register"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

proto.fields.hdr = ProtoField.none("ebm.hdr", "Header")
proto.fields.hdr_plen = ProtoField.uint16("ebm.hdr.payload_len", "Payload Length")
proto.fields.hdr_flags = ProtoField.bytes("ebm.hdr.flags", "Flags")
proto.fields.hdr_code = ProtoField.bool("ebm.hdr.code", "Response", 8, { "this is a response", "this is a request" }, 0x80)
proto.fields.hdr_mode = ProtoField.uint8("ebm.hdr.mode", "Mode", base.DEC, vs_mode, 0x03)
proto.fields.hdr_seq = ProtoField.uint32("ebm.hdr.seq", "Sequence Number")
proto.fields.hdr_status = ProtoField.uint8("ebm.hdr.status", "Status", nil, vs_status)
proto.fields.payload = ProtoField.none("ebm.payload", "Payload")

proto.fields.cmd = ProtoField.none("ebm.cmd", "Command", base.NONE)
proto.fields.cmd_type = ProtoField.uint8("ebm.cmd.type", "Type", nil, vs_cmd_type)
--
proto.fields.cmd_read_reg = ProtoField.uint16("ebm.cmd.read_reg", "Address", base.HEX, vs_register)
proto.fields.cmd_read_len = ProtoField.uint16("ebm.cmd.read_len", "Length")
--
proto.fields.data = ProtoField.bytes("ebm.data", "Data")
proto.fields.padding = ProtoField.bytes("ebm.padding", "Padding")

proto.experts.assert = ProtoExpert.new("ebm.assert", "Protocol", expert.group.ASSUMPTION, expert.severity.WARN)

local f_plen = Field.new("ebm.hdr.payload_len")
local f_code = Field.new("ebm.hdr.code")
local f_seq = Field.new("ebm.hdr.seq")

proto.fields.frame_request = ProtoField.framenum("ebm.request", "Request In", nil, frametype.REQUEST)
proto.fields.frame_response = ProtoField.framenum("ebm.response", "Response In", nil, frametype.RESPONSE)

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
	-- |         Payload Length        |     Flags     |    Sequence   :
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- :                   Sequence                    |     Status    |
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |            Payload...
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	-- |            Padding...
	-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	-- Payload Length (plen)
	--
	--    Request - Length of payload field
	--
	--    Response - Length of payload incremented by six (6)
	--               (header length excluding 'plen' field)
	--
	-- Flags
	--        0 1 2 3 4 5 6 7
	--       +-+-+-+-+-+-+-+-+
	--       |C 0 0 0 0 0 M M|
	--       +-+-+-+-+-+-+-+-+
	--
	--    C (Code)
	--
	--        0 - Response
	--
	--        1 - Request
	--
	--    M (Mode)
	--
	--        1 - Query
	--
	--        2 - ???
	--
	-- Status
	--
	--    0 - Success
	--
	--  255 - Not applicable

	local hdr_tvb = tvb(0, 8)
	local hdr_tree = ebm_tree:add(proto.fields.hdr, hdr_tvb())

	local payload_len_tree = hdr_tree:add(proto.fields.hdr_plen, hdr_tvb(0, 2))

	local hdr_flags_tvb = hdr_tvb(2, 1)
	local hdr_flags = hdr_tree:add(proto.fields.hdr_flags, hdr_flags_tvb())

	if bit.band(hdr_flags_tvb():uint(), 0x7c) ~= 0 then
		hdr_flags:add_proto_expert_info(proto.experts.assert, "Flag bits 1-5 not all unset")
	end

	hdr_flags:add(proto.fields.hdr_code, hdr_flags_tvb())
	hdr_flags:add(proto.fields.hdr_mode, hdr_flags_tvb())

	local response = f_code()()

	pinfo.cols.info:append(response and ": Response" or ": Query")

	hdr_tree:add(proto.fields.hdr_seq, hdr_tvb(3, 4))
	local seq = f_seq()()
	if pinfo.visited then
		hdr_tree:add(proto.fields[response and "frame_request" or "frame_response"], requests[seq][not response]):set_generated()
	else
		if not requests[seq] then requests[seq] = { ["cmds"] = {} } end
		requests[seq][response] = pinfo.number
	end

	hdr_tree:add(proto.fields.hdr_status, hdr_tvb(7, 1))
	local hdr_status_tvb = hdr_tvb(7, 1)
	if not ((response and hdr_status_tvb:uint() == 0x00) or (not response and hdr_status_tvb:uint() == 0xff)) then
		hdr_tree:add_proto_expert_info(proto.experts.assert, "Status has unexpected value")
	end

	local payload_len = f_plen()()
	if response then payload_len = payload_len - 6 end
	local payload_tvb, payload_tree
	if payload_len > 0 then
		payload_tvb = tvb(8, payload_len)
		payload_tree = ebm_tree:add(proto.fields.payload, payload_tvb())
		if response then payload_len_tree:append_text(" (inc hdr ex plen [= 6 bytes])") end
	end

	if tvb:len() > 8 + payload_len then
		local padding_tvb = tvb(8 + payload_len)
		local padding_tree = ebm_tree:add(proto.fields.padding, padding_tvb())
		for i=1, padding_tvb:len() - 1 do
			if padding_tvb(i, 1):uint() ~= 0 then
				padding_tree:add_proto_expert_info(proto.experts.assert, "Padding has non-zero bytes")
				break
			end
		end
	end

	if payload_len == 0 then
		return len
	end

	local pi, pi_tvb
	local offset = 0
	if response then
		--  0                   1                   2                   3
		--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |                             Data...
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		--
		-- Data
		--
		--    Length comes from request
		--
		--    Note: only ever seen three (3) octets
		--

		local cmds = requests[seq]["cmds"]
		for i, cmd in pairs(cmds) do
			if offset >= payload_len then
				payload_tree:add_proto_expert_info(proto.experts.assert, "Truncated Response")
				break
			end

			-- handle format unknown
			if not cmd[2] then cmd[2] = payload_len - offset end

			pi_tvb = payload_tvb(offset, math.min(cmd[2], payload_len - offset))
			pi = payload_tree:add(proto.fields.data, pi_tvb())
			offset = offset + pi_tvb:len()

			if pinfo.visited then
				local gpi = pi:add(proto.fields.cmd):set_generated()
				gpi:add(proto.fields.cmd_type, cmd[1])
				if cmd[1] == CMD.read_reg then
					gpi:add(proto.fields.cmd_read_reg, cmd[3])
					gpi:add(proto.fields.cmd_read_len, cmd[2])
				end
			end

			if not cmd[2] then
				pi:add_proto_expert_info(proto.experts.assert, "Format Unknown")
				break
			elseif pi_tvb:len() < cmd[2] then
				pi:add_proto_expert_info(proto.experts.assert, "Truncated Data")
				break
			end
		end
	else
		while offset < payload_len do
			if offset >= payload_len then
				payload_tree:add_proto_expert_info(proto.experts.assert, "Truncated Request")
				break
			end

			local type = payload_tvb(offset, 1):uint()
			if type == CMD.read_reg then
				--  0                   1                   2                   3
				--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |   Type = 1    |                    Register                   |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |        Register Length        |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				pi_tvb = payload_tvb(offset, 6)
				pi = payload_tree:add(proto.fields.cmd, pi_tvb())
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd_type, pi_tvb(0, 1))
				pi:add(proto.fields.cmd_read_reg, pi_tvb(1, 3))
				pi:add(proto.fields.cmd_read_len, pi_tvb(4, 2))
				if pi_tvb(4, 2):uint() ~= 3 then
					pi:add_proto_expert_info(proto.experts.assert, "Register Length expected to be 3")
				end

				if not pinfo.visited then
					table.insert(requests[seq]["cmds"], { type, pi_tvb(4, 2):uint(), pi_tvb(1, 3):uint() })
				end
			elseif type == 2 then	-- ???
				--  0                   1                   2                   3
				--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |   Type = 2    |                    Register                   |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				-- |        Register Length        |
				-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				pi_tvb = payload_tvb(offset, 6)
				pi = payload_tree:add(proto.fields.cmd, pi_tvb())
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd_type, pi_tvb(0, 1))

				if not pinfo.visited then
					table.insert(requests[seq]["cmds"], { type, pi_tvb(4, 2):uint(), pi_tvb(1, 3):uint() })
				end
			else
				pi_tvb = payload_tvb(offset)
				pi = payload_tree:add(proto.fields.cmd, pi_tvb)
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd_type, pi_tvb(0, 1))

				pi:add_proto_expert_info(proto.experts.assert, "Unknown Command")

				if not pinfo.visited then
					table.insert(requests[seq]["cmds"], { type })
				end
			end
		end
	end

	return len
end

DissectorTable.get("ethertype"):add(0x6120, proto)
