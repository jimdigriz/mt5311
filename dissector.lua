-- The Ethernet Boot & Management (EBM) protocol smells like an
-- RPC for I2C. You ask for a register and it returns its value.
--
-- Everything is guess work, so errors are guarenteed!
--
-- Assumptions are codified with expert.group.ASSUMPTION

local vs_dir = {
	[1]	= "Response",
	[2]	= "Request"
}

local vs_mode = {
	[1]	= "Read",
	[2]	= "Write"
}

local vs_register = {}
function read_register_map ()
	local status

	local line_count = 0
	local warn = function (msg)
		print("mt5311 dissector.lua: line " .. tostring(line_count) .. " " .. msg .. ", ignoring")
	end
	for line in io.lines(__DIR__ .. (__DIR__:len() > 0 and __DIR_SEPARATOR__ or "") .. "register.map") do
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
				if vs_register[r[1]] then
					warn("duplicate register")
				elseif #r == 2 then
					vs_register[r[1]] = r[2]
				end
			else
				warn("unparsable register value in register.map")
			end
		elseif #r ~= 0 then
				warn("unparsable in register.map")
		end
	end
end
read_register_map()

local SEQ = {
	HELLO_CLIENT		= 0x6c360000,
	HELLO_SERVER		= 0x6c364556
}

local vs_status = {
	[0] = "Success",
	[255] = "No error"
}

local proto = Proto.new("EBM", "Ethernet Boot & Management Protocol")

proto.fields.hdr = ProtoField.none("ebm.hdr", "Header")
proto.fields.hdr_plen = ProtoField.uint16("ebm.hdr.payload_len", "Payload Length")
proto.fields.hdr_flags = ProtoField.uint8("ebm.hdr.flags", "Flags", base.HEX)
proto.fields.hdr_dir = ProtoField.bool("ebm.hdr.dir", "Direction", 8, vs_dir, 0x80)
proto.fields.hdr_mode = ProtoField.uint8("ebm.hdr.mode", "Mode", base.DEC, vs_mode, 0x03)
proto.fields.hdr_seq = ProtoField.uint32("ebm.hdr.seq", "Sequence Number")
proto.fields.hdr_status = ProtoField.uint8("ebm.hdr.status", "Status", nil, vs_status)
proto.fields.payload = ProtoField.none("ebm.payload", "Payload")
proto.fields.padding = ProtoField.none("ebm.padding", "Padding")

proto.fields.cmd = ProtoField.none("ebm.cmd", "Command")
proto.fields.cmd_type = ProtoField.uint8("ebm.cmd.type", "Type")
--
proto.fields.cmd_read_reg = ProtoField.uint24("ebm.cmd.reg", "Register Address", base.HEX, vs_register)
proto.fields.cmd_read_len = ProtoField.uint16("ebm.cmd.reglen", "Register Length")
proto.fields.cmd_read_val = ProtoField.uint24("ebm.cmd.regval", "Register Value", base.HEX)
--
proto.fields.data = ProtoField.bytes("ebm.data", "Data")
--

proto.fields.frame_request = ProtoField.framenum("ebm.request", "Request In", nil, frametype.REQUEST)
proto.fields.frame_response = ProtoField.framenum("ebm.response", "Response In", nil, frametype.RESPONSE)

proto.experts.seq = ProtoExpert.new("ebm.seq.magic", "Sequence Magic", expert.group.SEQUENCE, expert.severity.NOTE)
proto.experts.assert = ProtoExpert.new("ebm.assert", "Protocol", expert.group.ASSUMPTION, expert.severity.WARN)

local f_plen = Field.new("ebm.hdr.payload_len")
local f_dir = Field.new("ebm.hdr.dir")
local f_mode = Field.new("ebm.hdr.mode")
local f_seq = Field.new("ebm.hdr.seq")
local f_status = Field.new("ebm.hdr.status")

-- conversation tracking for populating
-- frametype and reconciling reads with data
local convlist, convlist_pre

function proto.init ()
	convlist = {}
	convlist_pre = {}
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
	-- Sequence
	--
	--    Starts at 1 (not zero) and increments for each request
	--
	--    There are two magic numbers:
	--
	--       0x6c360000 - Client Hello Handshake (request)
	--
	--       0x6c364556 - Server Hello Handshake (response)
	--
	-- Flags
	--
	--        0 1 2 3 4 5 6 7
	--       +-+-+-+-+-+-+-+-+
	--       |D ? ? ? ? ? M M|
	--       +-+-+-+-+-+-+-+-+
	--
	--    D (Direction)
	--
	--       0 - Response
	--
	--           Note: if sequence is a magic number D = 0 always
	--
	--       1 - Request
	--
	--    M (Mode)
	--
	--       1 - Read
	--
	--       2 - Write
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

	hdr_flags:add(proto.fields.hdr_dir, hdr_flags_tvb())
	hdr_flags:add(proto.fields.hdr_mode, hdr_flags_tvb())

	local hdr_seq_tree = hdr_tree:add(proto.fields.hdr_seq, hdr_tvb(3, 4))
	local seq = f_seq()()

	if seq == SEQ.HELLO_CLIENT or seq == SEQ.HELLO_SERVER then
		hdr_seq_tree:add_proto_expert_info(proto.experts.seq):append_text(" (" .. ((seq == SEQ.HELLO_CLIENT) and "Client" or "Server") .. " Hello)")
	end

	local response = (seq == SEQ.HELLO_CLIENT or seq == SEQ.HELLO_SERVER) and (seq == SEQ.HELLO_SERVER) or f_dir()()
	local server = response and pinfo.src or pinfo.dst
	local client = response and pinfo.dst or pinfo.src
	local dev = tostring(server) .. " " .. tostring(client)

	pinfo.cols.info:append(response and ": Response" or ": Request")

	if pinfo.visited then
		hdr_tree:add(proto.fields["frame_" .. (response and "request" or "response")], convlist[pinfo.number].partner):set_generated()
	else
		-- convlist_pre is used to temporarily hold the request frame number
		-- for the response to discover. It is keyed by 'dev' (server MAC
		-- concatenated with client MAC) and then by the sequence
		-- number. When the response is processed, it looks here for
		-- the request's frame number and then sets up convlist.
		-- When handshakes are detected, convlist_pre[dev] is flushed.

		convlist[pinfo.number] = {}

		if not convlist_pre[dev] then
			convlist_pre[dev] = {}
		end

		if not response then
			if seq == SEQ.HELLO_CLIENT then
				convlist_pre[dev] = {}
			end

			convlist_pre[dev][seq] = pinfo.number
		else
			if seq == SEQ.HELLO_SERVER then
				seq = SEQ.HELLO_CLIENT
			end

			-- guard incase we never see the request
			if convlist_pre[dev] and convlist_pre[dev][seq] then
				convlist[pinfo.number].partner = convlist_pre[dev][seq]
				convlist[convlist_pre[dev][seq]].partner = pinfo.number
				table.remove(convlist_pre[dev], seq)
			end

			if seq == SEQ.HELLO_SERVER then
				convlist_pre[dev] = {}
			end
		end
	end

	hdr_tree:add(proto.fields.hdr_status, hdr_tvb(7, 1))
	local hdr_status = f_status()()
	if not ((response and hdr_status == 0x00) or (not response and hdr_status == 0xff)) then
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
	local records = 0
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
		--    Note: only observed three (3) octets
		--

		local cmds = convlist[convlist[pinfo.number].partner].cmds
		for i, cmd in pairs(cmds) do
			records = records + 1

			if offset >= payload_len then
				payload_tree:add_proto_expert_info(proto.experts.assert, "Truncated Response")
				break
			end

			pi_tvb = payload_tvb(offset, math.min(cmd[3], payload_len - offset))
			pi = payload_tree:add(proto.fields.data, pi_tvb())
			offset = offset + pi_tvb:len()

			if pinfo.visited then
				local gpi = pi:add(proto.fields.cmd):set_generated()
				gpi:add(proto.fields.cmd_type, cmd[1])
				gpi:add(proto.fields.cmd_read_reg, cmd[2])
			end

			if pi_tvb:len() < cmd[3] then
				pi:add_proto_expert_info(proto.experts.assert, "Truncated Data")
				break
			end
		end
	else
		--  0                   1                   2                   3
		--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |      Type     |                    Register                   |
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |        Register Length        |              Value            :
		-- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		-- |     Value     |
		-- +-+-+-+-+-+-+-+-+
		--
		-- Type
		--
		--    1 - ???
		--
		--    2 - ???
		--
		-- Value
		--
		--    The Value field is three octets, and is present only when M is
		--    set to two (2) indicating write.

		if not pinfo.visited then
			convlist[pinfo.number].cmds = {}
		end

		while offset < payload_len do
			records = records + 1

			if offset >= payload_len then
				payload_tree:add_proto_expert_info(proto.experts.assert, "Truncated Request")
				break
			end

			local cmd_type = payload_tvb(offset, 1):uint()

			if cmd_type == 1 then
				local mode = f_mode()()

				pi_tvb = payload_tvb(offset, mode == 1 and 6 or 9)
				pi = payload_tree:add(proto.fields.cmd, pi_tvb())
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd_type, pi_tvb(0, 1))

				pi:add(proto.fields.cmd_read_reg, pi_tvb(1, 3))
				pi:add(proto.fields.cmd_read_len, pi_tvb(4, 2))
				if pi_tvb(4, 2):uint() ~= 3 then
					pi:add_proto_expert_info(proto.experts.assert, "Register Length expected to be 3")
				end
				if mode == 2 then
					pi:add(proto.fields.cmd_read_val, pi_tvb(6, 3))
				end

				if not pinfo.visited then
					table.insert(convlist[pinfo.number].cmds, { cmd_type, pi_tvb(1, 3):uint(), pi_tvb(4, 2):uint() })
				end
			else
				pi_tvb = payload_tvb(offset)
				pi = payload_tree:add(proto.fields.cmd, pi_tvb())
				offset = offset + pi_tvb:len()

				pi:add(proto.fields.cmd_type, pi_tvb(0, 1))

				pi:add_proto_expert_info(proto.experts.assert, "Command Type expected to be 1")
			end
		end
	end

	payload_tree:append_text(" [" .. tostring(records) .. " record(s)]")

	return len
end

set_plugin_info({
	version = "0.1",
	author = "Alexander Clouter",
	email = "alex@digriz.org.uk",
	copyright = "Copyright (c) 2023, coreMem Limited.",
	license = "AGPLv3 license",
	repository = "https://github.com/jimdigriz/mt5311"
})
DissectorTable.get("ethertype"):add(0x6120, proto)
