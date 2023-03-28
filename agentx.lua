-- SNMP AgentX Subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://datatracker.ietf.org/doc/html/rfc2741

local bit32 = require "bit32"
local socket = require "posix.sys.socket"
local poll = require "posix.poll"
local unistd = require "posix.unistd"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(arg[0]:match("^(.-/?)[^/]+.lua$") .. "struct.lua"))()
end

local unpack = table.unpack or _G.unpack

local HDRSIZE = 20

local FLAGS = {
	INSTANCE_REGISTRATION	= 0x01,
	NEW_INDEX		= 0x02,
	ANY_INDEX		= 0x04,
	NON_DEFAULT_CONTEXT	= 0x08,
	NETWORK_BYTE_ORDER	= 0x10
}

local PTYPE = {
	_hdr			= 0,
	open			= 1,
	close			= 2,
	register		= 3,
	unregister		= 4,
	indexAllocate		= 14,
	indexDeallocate		= 15,
	response		= 18
}

local VTYPE = {
	integer			= 2,
	octetstring		= 4,
	objectid		= 6
}

local ERROR = {
	noAgentXError		= 0,
	duplicateRegistration	= 263
}

local REASON = {
	other			= 1,
	parseError		= 2,
	protocolError		= 3,
	timeouts		= 4,
	shutdown		= 5,
	byManager		= 6
}

local val = { enc = {}, dec = {} }

function val.enc.objectid (v, i)
	local prefix = 0
	if #v > 4 and v[1] == 1 and v[2] == 3 and v[3] == 6 and v[4] == 1 then
		prefix = v[5]
		v = {unpack(v, 6)}
	end

	local include = i and 1 or 0

	return struct.pack(">BBBB" .. string.rep("I", #v), #v, prefix, include, 0, unpack(v))
end

function val.dec.objectid (pkt)
	local len, prefix, include, reserved = struct.unpack(">BBBB", pkt)
	pkt = pkt:sub(5)
	local v = {struct.unpack(">" .. string.rep("I", len), pkt)}
	if prefix > 0 then
		v = {1,3,6,1,prefix,unpack(v)}
	end
	return pkt:sub(1 + 4 * len), v, include
end

function val.enc.searchrange (t)
	return val.objectid(t.start, t.include) .. val.objectid(t["end"])
end

function val.dec.searchrange (pkt)
	error("nyi")
end

function val.enc.octetstring (v)
	v = v or ""
	return struct.pack(">I", v:len()) .. v .. string.rep("\0", 4 - v:len() % 4)
end

function val.dec.octetstring (pkt)
	local len = struct.unpack(">I", pkt)
	return pkt:sub(5 + len + (4 - len % 4)), pkt:sub(5, len)
end

function val.enc.varbind (t)
	local data
	if t.type == VTYPE.integer then
		data = struct.pack(">I", t.data or 0)
	elseif t.type == VTYPE.octetstring then
		data = val.enc.octetstring(t.data)
	else
		error("nyi")
	end
	return struct.pack(">H", t.type) .. "\0\0" .. val.enc.objectid(t.name) .. data
end

function val.dec.varbind (pkt)
	local vtype = struct.unpack(">H", pkt)
	pkt = pkt:sub(5)

	local pkt, name, include = val.dec.objectid(pkt)
	local data

	if vtype == VTYPE.integer then
		data = struct.unpack(">I", pkt)
		pkt = pkt:sub(5)
	elseif vtype == VTYPE.octetstring then
		pkt, data = val.dec.octetstring(pkt)
	elseif vtype == VTYPE.objectid then
		pkt, data = val.dec.objectid(pkt)
	else
		error("nyi " .. tostring(vtype))
	end
	return pkt, { ["type"] = vtype, name = name, data = data }
end

local pdu = { enc = {}, dec = {} }

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.1
pdu.enc_hdr = function (s, t)
	local flags = bit32.bor(t.flags and t.flags or 0x00, FLAGS.NETWORK_BYTE_ORDER)
	local packetID = s._packetID
	s._packetID = packetID + 1
	return struct.pack(">BBBBIIII", 1, t.type, flags, 0, s._sessionID, 0, packetID, t.payload:len()) .. t.payload
end

pdu.dec_hdr = function (pkt)
	local version, ptype, flags, reserved, sessionID, transactionID, packetID, payload_length = struct.unpack(">BBBBIIII", pkt)
	return {
		version		= version,
		["type"]	= ptype,
		flags		= flags,
		sessionID	= sessionID,
		transactionID	= transactionID,
		packetID	= packetID,
		payload_length	= payload_length
	}
end

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.1
pdu.enc[PTYPE.open] = function (s, t)
	local deadtime = t.deadtime or 0
	local payload = struct.pack(">B", deadtime) .. "\0\0\0" .. val.enc.objectid({}) .. val.enc.octetstring(t.name)
	return pdu.enc_hdr(s, {["type"]=PTYPE.open, payload=payload})
end

pdu.enc[PTYPE.close] = function (s, t)
	t = t or {}
	local reason = t.reason or REASON.other
	local payload = struct.pack(">B", reason) .. "\0\0\0"
	return pdu.enc_hdr(s, {["type"]=PTYPE.close, payload=payload})
end

pdu.dec[PTYPE.close] = function (res, pkt)
	local reason = struct.unpack(">B", pkt)
	res.reason = reason
	return res
end

pdu.enc[PTYPE.register] = function (s, t)
	local timeout = t.timeout or 0
	local priority = t.priority or 127
	local range_subid = t.range_subid or 0
	local payload = struct.pack(">BBBB", timeout, priority, range_subid, 0) .. val.enc.objectid(t.subtree)
	if range_subid > 0 then
		payload = payload .. struct.pack(">I", t.upper_bound)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.register, payload=payload})
end

pdu.enc[PTYPE.indexAllocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind) do
		payload = payload .. val.enc.varbind(v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.indexAllocate, payload=payload, flags=t.flags})
end

pdu.enc[PTYPE.indexDeallocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind) do
		payload = payload .. val.enc.varbind(v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.indexDeallocate, payload=payload, flags=t.flags})
end

pdu.dec[PTYPE.response] = function (self, res, pkt)
	local sysUpTime, perror, index = struct.unpack(">IHH", pkt)
	res.sysUpTime = sysUpTime
	res.error = perror
	res.index = index

	res.varbind = {}
	pkt = pkt:sub(9)
	while pkt:len() > 0 do
		local varbind
		pkt, varbind = val.dec.varbind(pkt)
		table.insert(res.varbind, varbind)
	end

	return res
end

local M = { type = VTYPE, flags = FLAGS, error = ERROR }

function M:session (t)
	t = t or {}

	setmetatable({ __gc = function() M:close() end }, self)
	self.__index = self

	t.name = t.name or "Lua AgentX"
	t.path = t.path or "/var/agentx/master"
	t.deadtime = 0

	self._sessionID = 0
	self._packetID = 0

	self.fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0))
	local ok, err, e = socket.connect(self.fd, { family=socket.AF_UNIX, path=t.path })
	if not ok then
		M:close()
		return nil, err
	end

	M:send(pdu.enc[PTYPE.open](self, t))
	local r = poll.rpoll(self.fd, 100)
	if r == 0 then
		M:close()
		return nil, "no response"
	end

	local res = M:recv()
	if res.error ~= ERROR.noAgentXError then
		M:close()
		return nil, "AgentX master returned error code " .. tostring(res.error)
	end

	self._sessionID = res._hdr.sessionID

	return self
end

function M:close ()
	if self._sessionID ~= nil then
		M:send(pdu.enc[PTYPE.close](self))
		local res = M:recv()
		if res and res.error ~= ERROR.noAgentXError then
			return false, "AgentX master returned error code " .. tostring(res.error)
		end
		self._sessionID = nil
	end
	if self.fd ~= nil then
		unistd.close(self.fd)
		self.fd = nil
	end
	return true
end

function M:register (t)
	M:send(pdu.enc[PTYPE.register](self, t))
	return M:recv()
end

function M:index_allocate (t)
	if t.name then
		t = { flags = t.flags, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	M:send(pdu.enc[PTYPE.indexAllocate](self, t))
	return M:recv()
end

function M:index_deallocate (t)
	if t.name then
		t = { flags = t.flags, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	M:send(pdu.enc[PTYPE.indexDeallocate](self, t))
	return M:recv()
end

function M:send (msg)
	assert(socket.send(self.fd, msg) == msg:len())
end

function M:recv ()
	-- stream socket so keep pulling...
	local hdr = ""
	while true do
		local buf = socket.recv(self.fd, HDRSIZE - hdr:len())
		if buf:len() == 0 then
			self._sessionID = nil
			self.fd = nil
			return nil, "connection closed"
		end
		hdr = hdr .. buf
		if hdr:len() == 20 then break end
	end

	local res = { _hdr = pdu.dec_hdr(hdr) }

	-- for now this is all we support
	assert(res._hdr.type == PTYPE.response)

	local payload = ""
	while true do
		payload = payload .. socket.recv(self.fd, res._hdr.payload_length - payload:len())
		if payload:len() == res._hdr.payload_length then break end
	end

	return pdu.dec[res._hdr.type](self, res, payload)
end

return M
