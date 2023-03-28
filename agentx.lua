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

local DEADTIME = 3
local HDRSIZE = 20

local FLAGS = {
	INSTANCE_REGISTRATION	= 0x01,
	NEW_INDEX		= 0x02,
	ANY_INDEX		= 0x04,
	NON_DEFAULT_CONTEXT	= 0x08,
	NETWORK_BYTE_ORDER	= 0x10
}

local TYPE = {
	_hdr		= 0,
	open		= 1,
	close		= 2,
	indexAllocate	= 14,
	indexDeallocate	= 15,
	response	= 18
}

local VTYPE = {
	integer		= 2,
	octetstring	= 4
}

local ERROR = {
	noAgentXError	= 0
}

local REASON = {
	other		= 1,
	parseError	= 2,
	protocolError	= 3,
	timeouts	= 4,
	shutdown	= 5,
	byManager	= 6
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

function val.enc.searchrange (s, e, i)
	return val.objectid(s, i) .. val.objectid(e)
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

function val.enc.varbind (vtype, name, data)
	if vtype == VTYPE.integer then
		data = struct.pack(">I", data or 0)
	elseif vtype == VTYPE.octetstring then
		data = val.enc.octetstring(data)
	else
		error("nyi")
	end
	return struct.pack(">H", vtype) .. "\0\0" .. val.enc.objectid(name) .. data
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
	else
		error("nyi")
	end
	return pkt, vtype, name, data
end

local pdu = { enc = {}, dec = {} }

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.1
pdu.enc_hdr = function (self, t)
	local flags = bit32.bor(t.flags and t.flags or 0x00, FLAGS.NETWORK_BYTE_ORDER)
	return struct.pack(">BBBBIIII", 1, t.type, flags, 0, self._sessionID, 0, 0, t.payload:len()) .. t.payload
end

pdu.dec_hdr = function (self, pkt)
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
pdu.enc[TYPE.open] = function (self, t)
	local deadtime = t.deadtime or DEADTIME
	local payload = struct.pack(">B", deadtime) .. "\0\0\0" .. val.enc.objectid({}) .. val.enc.octetstring(t.name)
	return pdu.enc_hdr(self, {["type"]=TYPE.open, payload=payload})
end

pdu.enc[TYPE.close] = function (self, t)
	t = t or {}
	local reason = t.reason or REASON.other
	local payload = struct.pack(">B", reason) .. "\0\0\0"
	return pdu.enc_hdr(self, {["type"]=TYPE.close, payload=payload})
end

pdu.dec[TYPE.close] = function (self, res, pkt)
	local reason = struct.unpack(">B", pkt)
	res.reason = reason
	return res
end

pdu.enc[TYPE.indexAllocate] = function (self, t)
	local payload = ""
	for i, v in ipairs(t) do
		payload = payload .. val.enc.varbind(v.type, v.name)
	end
	return pdu.enc_hdr(self, {["type"]=TYPE.indexAllocate, payload=payload, flags=t.flags})
end

pdu.enc[TYPE.indexDeallocate] = function (self, t)
	local payload = ""
	for i, v in ipairs(t) do
		payload = payload .. val.enc.varbind(v.type, v.name, v.data)
	end
	return pdu.enc_hdr(self, {["type"]=TYPE.indexDeallocate, payload=payload, flags=t.flags})
end

pdu.dec[TYPE.response] = function (self, res, pkt)
	local sysUpTime, perror, index = struct.unpack(">IHH", pkt)
	res.sysUpTime = sysUpTime
	res.error = perror
	res.index = index

	res.varbind = {}
	pkt = pkt:sub(9)
	while pkt:len() > 0 do
		local vtype, name, data
		pkt, vtype, name, data = val.dec.varbind(pkt)
		table.insert(res.varbind, { ["type"] = vtype, name = name, data = data })
	end

	return res
end

local M = { type = VTYPE, flags = FLAGS }

function M:session (t)
	t = t or {}

	setmetatable({ __gc = function() M:close() end }, self)
	self.__index = self

	t.name = t.name or "Lua AgentX"
	t.path = t.path or "/var/agentx/master"
	t.deadtime = t.deadtime or DEADTIME

	self._sessionID = 0
	self._indexes = {}

	self.fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0))
	local ok, err, e = socket.connect(self.fd, { family=socket.AF_UNIX, path=t.path })
	if not ok then
		M:close()
		return nil, err
	end

	M:send(pdu.enc[TYPE.open](self, t))
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
	for i=#self._indexes,1,-1 do
		M:index_deallocate(self._indexes[i])
	end
	if self._sessionID ~= nil then
		M:send(pdu.enc[TYPE.close](self))
		local res = M:recv()
		if res.error ~= ERROR.noAgentXError then
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

function M:index_allocate (t)
	if t.name then
		t = {t}
	end
	M:send(pdu.enc[TYPE.indexAllocate](self, t))
	local res = M:recv()
	if res.error ~= ERROR.noAgentXError then
		return nil, "AgentX master returned error code " .. tostring(res.error)
	end
	for i, v in ipairs(res.varbind) do
		table.insert(self._indexes, v)
	end
	return res
end

function M:index_deallocate (t)
	if t.name then
		t = {t}
	end
	M:send(pdu.enc[TYPE.indexDeallocate](self, t))
	local res = M:recv()
	if res.error ~= ERROR.noAgentXError then
		return nil, "AgentX master returned error code " .. tostring(res.error)
	end
	for ti, tt in ipairs(t) do
		for i, v in ipairs(self._indexes) do
			if table.concat(tt.name, ".") == table.concat(v.name, ".") and tt.data == v.data then
				table.remove(self._indexes, i)
				break
			end
		end
	end
	return res
end

function M:send (msg)
	assert(socket.send(self.fd, msg) == msg:len())
end

function M:recv ()
	-- stream socket so keep pulling...
	local hdr = ""
	while true do
		hdr = hdr .. socket.recv(self.fd, HDRSIZE - hdr:len())
		if hdr:len() == 20 then break end
	end

	local res = { _hdr = pdu.dec_hdr(self, hdr) }

	-- for now this is all we support
	assert(res._hdr.type == TYPE.response)

	local payload = ""
	while true do
		payload = payload .. socket.recv(self.fd, res._hdr.payload_length - payload:len())
		if payload:len() == res._hdr.payload_length then break end
	end

	local status, res = pcall(function() return pdu.dec[res._hdr.type](self, res, payload) end)
	if not status then
		error("nyi decode for " .. tostring(res._hdr.type))
	end

	return res
end

return M
