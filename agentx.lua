-- SNMP AgentX Subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://datatracker.ietf.org/doc/html/rfc2741

local bit32 = require "bit32"
local errno = require "posix.errno"
local fcntl = require "posix.fcntl"
local poll = require "posix.poll"
local socket = require "posix.sys.socket"
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
	_SearchRange		= -2,
	_VarBind		= -1,
	Integer			= 2,
	OctetString		= 4,
	Null			= 5,
	ObjectIdentifer		= 6,
	IpAddress		= 64,
	Counter32		= 65,
	Gauge32			= 66,
	TimeTicks		= 67,
	Opaque			= 68,
	Counter64		= 67,
	noSuchobject		= 128,
	noSuchInstance		= 129,
	endOfMibView		= 130
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

val.enc[VTYPE.ObjectIdentifer] = function (v, i)
	local prefix = 0
	if #v > 4 and v[1] == 1 and v[2] == 3 and v[3] == 6 and v[4] == 1 then
		prefix = v[5]
		v = {unpack(v, 6)}
	end

	local include = i and 1 or 0

	return struct.pack(">BBBB" .. string.rep("I", #v), #v, prefix, include, 0, unpack(v))
end

val.dec[VTYPE.ObjectIdentifer] = function (pkt)
	local len, prefix, include, reserved = struct.unpack(">BBBB", pkt)
	pkt = pkt:sub(5)
	local v = {struct.unpack(">" .. string.rep("I", len), pkt)}
	if prefix > 0 then
		v = {1,3,6,1,prefix,unpack(v)}
	end
	return pkt:sub(1 + 4 * len), v, include
end

val.enc[VTYPE._SearchRange] = function (t)
	return val.objectid(t.start, t.include) .. val.objectid(t["end"])
end

val.dec[VTYPE._SearchRange] = function (pkt)
	local vstart, include, vend
	pkt, vstart, include = val.dec[VTYPE._VarBind](pkt)
	pkt, venv = val.dec[VTYPE._VarBind](pkt)
	return pkt, { start = vstart, include = include, ["end"] = vend }
end

val.enc[VTYPE.OctetString] = function (v)
	v = v or ""
	return struct.pack(">I", v:len()) .. v .. string.rep("\0", 4 - v:len() % 4)
end

val.dec[VTYPE.OctetString] = function (pkt)
	local len = struct.unpack(">I", pkt)
	return pkt:sub(5 + len + (4 - len % 4)), pkt:sub(5, len)
end

val.enc[VTYPE._VarBind] = function (t)
	local data
	if t.type == VTYPE.Integer then
		data = struct.pack(">I", t.data or 0)
	elseif t.type == VTYPE.OctetString then
		data = val.enc[VTYPE.OctetString](t.data)
	else
		error("nyi")
	end
	return struct.pack(">H", t.type) .. "\0\0" .. val.enc[VTYPE.ObjectIdentifer](t.name) .. data
end

val.dec[VTYPE._VarBind] = function (pkt)
	local vtype = struct.unpack(">H", pkt)
	pkt = pkt:sub(5)

	local pkt, name, include = val.dec[VTYPE.ObjectIdentifer](pkt)
	local data

	if vtype == VTYPE.Integer then
		data = struct.unpack(">I", pkt)
		pkt = pkt:sub(5)
	elseif vtype == VTYPE.OctetString then
		pkt, data = val.dec[VTYPE.OctetString](pkt)
	elseif vtype == VTYPE.ObjectIdentifer then
		pkt, data = val.dec[VTYPE.ObjectIdentifer](pkt)
	else
		error("nyi " .. tostring(vtype))
	end
	return pkt, { ["type"] = vtype, name = name, data = data }
end

local pdu = { enc = {}, dec = {} }

pdu.enc_hdr = function (s, t)
	local flags = bit32.bor(t.flags and t.flags or 0x00, FLAGS.NETWORK_BYTE_ORDER)
	local sessionID = s._sessionID or 0
	return struct.pack(">BBBBIIII", 1, t.type, flags, 0, sessionID, 0, s._packetID, t.payload:len()) .. t.payload
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
	local payload = struct.pack(">B", deadtime) .. "\0\0\0" .. val.enc[VTYPE.ObjectIdentifer]({}) .. val.enc[VTYPE.OctetString](t.name)
	return pdu.enc_hdr(s, {["type"]=PTYPE.open, payload=payload})
end

pdu.enc[PTYPE.close] = function (s, t)
	t = t or {}
	local reason = t.reason or REASON.other
	local payload = struct.pack(">B", reason) .. "\0\0\0"
	return pdu.enc_hdr(s, {["type"]=PTYPE.close, payload=payload})
end

pdu.dec[PTYPE.close] = function (pkt, res)
	local reason = struct.unpack(">B", pkt)
	res.reason = reason
	return pkt:sub(2), res
end

pdu.enc[PTYPE.register] = function (s, t)
	local timeout = t.timeout or 0
	local priority = t.priority or 127
	local range_subid = t.range_subid or 0
	local payload = struct.pack(">BBBB", timeout, priority, range_subid, 0) .. val.enc[VTYPE.ObjectIdentifer](t.subtree)
	if range_subid > 0 then
		payload = payload .. struct.pack(">I", t.upper_bound)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.register, payload=payload})
end

pdu.enc[PTYPE.indexAllocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind) do
		payload = payload .. val.enc[VTYPE._VarBind](v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.indexAllocate, payload=payload, flags=t.flags})
end

pdu.enc[PTYPE.indexDeallocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind) do
		payload = payload .. val.enc[VTYPE._VarBind](v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.indexDeallocate, payload=payload, flags=t.flags})
end

pdu.dec[PTYPE.response] = function (pkt, res)
	local sysUpTime, perror, index = struct.unpack(">IHH", pkt)
	res.sysUpTime = sysUpTime
	res.error = perror
	res.index = index

	res.varbind = {}
	pkt = pkt:sub(9)
	while pkt:len() > 0 do
		local varbind
		pkt, varbind = val.dec[VTYPE._VarBind](pkt)
		table.insert(res.varbind, varbind)
	end

	return pkt, res
end

local M = { type = VTYPE, flags = FLAGS, error = ERROR }

function M:session (t)
	t = t or {}

	setmetatable({ __gc = function() M:close() end }, self)
	self.__index = self

	t.name = t.name or "Lua AgentX"
	t.path = t.path or "/var/agentx/master"
	t.deadtime = 0

	self._sessionID = nil
	self._packetID = 0
	self._requests = {}

	self.fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0))
	local ok, err, e = socket.connect(self.fd, { family=socket.AF_UNIX, path=t.path })
	if not ok then
		M:close()
		return nil, err
	end

	-- https://github.com/luaposix/luaposix/issues/354
--	local fdflags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
--	assert(fcntl.fcntl(self.fd, fcntl.F_SETFL, bit32.bor(fdflags, fcntl.O_NONBLOCK)))

	self._producer = M:_producer_co()

	local status, result = M:_request(pdu.enc[PTYPE.open](self, t))
	if not status then
		error(result)
	end
	if result.error ~= ERROR.noAgentXError then
		error("AgentX master returned error code " .. tostring(result.error))
	end
	self._sessionID = result._hdr.sessionID

	return self
end

function M:close ()
	if self._sessionID ~= nil then
		local status, result = M:_request(pdu.enc[PTYPE.close](self))
		if not status then
			error(result)
		end
		if result and result.error ~= ERROR.noAgentXError then
			return false, "AgentX master returned error code " .. tostring(result.error)
		end
		self._sessionID = nil
	end
	if self.fd ~= nil then
		unistd.close(self.fd)
		self.fd = nil
	end
	return true
end

function M:process ()
	local status, result = coroutine.resume(self._producer)
	if not status then
		error(result)
	end
	if result and result._hdr.type == PTYPE.response then
		local co = self._requests[result._hdr.packetID]
		self._requests[result._hdr.packetID] = nil
		coroutine.resume(co, result)
	else
		coroutine.resume(self._consumer, result)
	end
end

function M:_producer_co ()
	return coroutine.create(function ()
		while true do
			local hdrpkt = ""
			while true do
				local buf, err = socket.recv(self.fd, HDRSIZE - hdrpkt:len())
				if not buf then
					if err == errno.EAGAIN then
						coroutine.yield()
					else
						error("recv() " .. err)
					end
				else
					if buf:len() == 0 then error("closed") end
					hdrpkt = hdrpkt .. buf
					if hdrpkt:len() == 20 then break end
					coroutine.yield()
				end
			end

			local hdr = pdu.dec_hdr(hdrpkt)
			assert(not self._sessionID or hdr.sessionID == self._sessionID)

			local payload = ""
			while true do
				local buf, err = socket.recv(self.fd, hdr.payload_length - payload:len())
				if not buf then
					if err == errno.EAGAIN then
						coroutine.yield()
					else
						error("recv() " .. err)
					end
				else
					if buf:len() == 0 then error("closed") end
					payload = payload .. buf
					if payload:len() == hdr.payload_length then break end
					coroutine.yield()
				end
			end

			local pkt, res = pdu.dec[hdr.type](payload, { _hdr = hdr })
			assert(pkt:len() == 0)
			coroutine.yield(res)
		end
	end)
end

function M:_request (msg, cb)
	assert(socket.send(self.fd, msg) == msg:len())

	local status, result
	local function _cb (...)
		status = true
		result = ...
	end
	local co = cb and cb or _cb
	if type(co) == "function" then co = coroutine.create(co) end

	self._requests[self._packetID] = co
	self._packetID = self._packetID + 1

	if not cb then
		while coroutine.status(co) ~= "dead" do
			M:process()
		end
		return status, result
	end

	return co
end

function M:register (t)
	return M:_request(pdu.enc[PTYPE.register](self, t))
end

function M:index_allocate (t)
	if t.name then
		t = { flags = t.flags, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	return M:_request(pdu.enc[PTYPE.indexAllocate](self, t))
end

function M:index_deallocate (t)
	if t.name then
		t = { flags = t.flags, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	return M:_request(pdu.enc[PTYPE.indexDeallocate](self, t))
end

return M
