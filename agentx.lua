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

local TYPE = {
	_hdr		= 0,
	open		= 1,
	response	= 18
}

local ERROR = {
	noAgentXError	= 0
}

local val = { enc = {}, dec = {} }

function val.enc.objectid (v, i)
	local prefix = 0
	if #v > 0 and v[1] < 256 then
		prefix = v[1]
		table.remove(v)
	end

	local include = i and 1 or 0

	return struct.pack(">BBBB" .. string.rep("I", #v), #v, prefix, include, 0, unpack(v))
end

function val.enc.searchrange (s, e, i)
	return val.objectid(s, i) .. val.objectid(e)
end

function val.enc.octetstring (v)
	return struct.pack(">I", v:len()) .. v .. string.rep("\0", 4 - v:len() % 4)
end

function val.enc.type ()
	error("nyi")
end

local pdu = { enc = {}, dec = {} }

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.1
pdu.enc[TYPE._hdr] = function (self, ptype, payload, flags)
	flags = bit32.bor(flags and flags or 0x00, 0x10)
	return struct.pack(">BBBBIIII", 1, ptype, flags, self.sessionID, 0, 0, 0, payload:len()) .. payload
end

pdu.dec[TYPE._hdr] = function (self, pkt)
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
pdu.enc[TYPE.open] = function (self)
	return pdu.enc[TYPE._hdr](self, TYPE.open, struct.pack(">B", DEADTIME) .. "\0\0\0" .. val.enc.objectid({}) .. val.enc.octetstring("EBM"))
end

pdu.dec[TYPE.response] = function (self, res, pkt)
	local sysUpTime, perror, index = struct.unpack(">IHH", pkt)
	res.sysUpTime = sysUpTime
	res.error = perror
	res.index = index
	return res
end

local M = {}

function M:session (t)
	t = t or {}

	setmetatable({ __gc = function() M:disconnect() end }, self)
	self.__index = self

	t.path = t.path or "/var/agentx/master"

	self.sessionID = 0

	self._fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0))
	local ok, err, e = socket.connect(self._fd, { family=socket.AF_UNIX, path=t.path })
	if not ok then
		M:disconnect()
		return nil, err
	end

	M:send(pdu.enc[TYPE.open](self))
	local r = poll.rpoll(self._fd, 100)
	if r == 0 then
		M:disconnect()
		return nil, "no response"
	end

	local res = M:recv()
	if res.error ~= ERROR.noAgentXError then
		M:disconnect()
		return nil, "AgentX master returned error code " .. tostring(res.error)
	end

	self.sessionID = res._hdr.sessionID

	return self
end

function M:disconnect ()
	if self._fd ~= nil then
		unistd.close(self_.fd)
		self._fd = nil
	end
end

function M:send (msg)
	assert(socket.send(self._fd, msg) == msg:len())
end

function M:recv ()
	-- stream socket so keep pulling...
	local hdr = ""
	while true do
		hdr = hdr .. socket.recv(self._fd, HDRSIZE - hdr:len())
		if hdr:len() == 20 then break end
	end

	local res = { _hdr = pdu.dec[TYPE._hdr](self, hdr) }

	-- for now this is all we support
	assert(res._hdr.type == TYPE.response)

	local payload = ""
	while true do
		payload = payload .. socket.recv(self._fd, res._hdr.payload_length - payload:len())
		if payload:len() == res._hdr.payload_length then break end
	end

	local status, res = pcall(function() return pdu.dec[res._hdr.type](self, res, payload) end)
	if not status then
		error("nyi decode for " .. tostring(res._hdr.type))
	end

	return res
end

return M
