-- SNMP AgentX Subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://datatracker.ietf.org/doc/html/rfc2741

-- https://luaposix.github.io/luaposix/examples/packet-socket.lua.html
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
local MAXSIZE = 9000

local val = { enc = {}, dec = {} }

function val.enc.objectid (v, i)
	local prefix = 0
	if v[1] < 256 then
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
	return struct.pack(">Ic0c0", v:len(), v, string.rep("\0", v:len() - (v:len() % 4)))
end

function val.enc.type ()
	error("nyi")
end

local pdu = {}

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.1
function pdu.open ()
	return struct.pack(">B", DEADTIME) .. "\0\0\0" .. "\0\0\0\0" .. val.enc.octetstring("EBM")
end

local M = {}

function M:session (t)
	t = t or {}

	setmetatable({ __gc = function() M:disconnect() end }, self)
	self.__index = self

	self._path = t.path or "/var/agentx/master"

	self._fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0))

	local msg = pdu.open()
	local status, err = pcall(function() return M:send(msg) end)
	if not status then
		return nil, err
	end
	print(M:recv())

	return self
end

function M:disconnect ()
	if self._fd ~= nil then
		unistd.close(self_.fd)
		self._fd = nil
	end
end

function M:send (msg)
	assert(socket.sendto(self._fd, msg, {family=socket.AF_UNIX, path=self._path}) == msg:len())
end

function M:recv ()
	local pkt = socket.recv(self._fd, MAXSIZE)
	return pkt
end

return M
