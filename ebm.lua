-- EBM Protocol
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

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

local PROTO = 0x6120
local MAXSIZE = 1500 - 14
local SEQ = {
	HELLO_CLIENT	= 0x6c360000,
	HELLO_SERVER	= 0x6c364556
}
local REG = {
	linktime	= 0x006d35
}

-- https://stackoverflow.com/a/23596380
local little_endian = string.dump(function() end):byte(7) == 1

local function htons (v)
	if little_endian then
		v = struct.unpack("H", struct.pack(">H", v))
	end
	return v
end

local function macaddr2bytes (v)
	local macaddr = {v:lower():match("^(%x%x)" .. string.rep("[:-]?(%x%x)", 5) .. "$")}
	if #macaddr ~= 6 then
		return nil
	end
	for i, v in ipairs(macaddr) do
		macaddr[i] = string.char(tonumber(v, 16))
	end
	macaddr = table.concat(macaddr, "")
	return macaddr
end

local M = {}

function M:session (t)
	setmetatable({ __gc = function() M:disconnect() end }, self)
	self.__index = self

	self._iface = t.iface

	-- luaposix does not support ioctl(fd, SIOCGIFHWADDR, &s))
	local macaddr = io.open("/sys/class/net/" .. self._iface .. "/address")
	if not macaddr then
		return nil, "invalid iface"
	end
	self._addr_local = macaddr2bytes(macaddr:read())
	assert(self._addr_local)
	macaddr:close()

	self._addr = macaddr2bytes(t.addr)
	if not self._addr then
		return nil, "invalid MAC address"
	end

	self._pending = false

	self._seq = 1

	-- luaposix does not support AF_PACKET/SOCK_DGRAM :(
	self._fd = assert(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(PROTO)))
	assert(socket.bind(self._fd, {family=socket.AF_PACKET, ifindex=socket.if_nametoindex(t.iface)}))

	-- handshake *seems* not to be necessary and may be more a check
	self:send({seq=SEQ.HELLO_CLIENT, status=0, payload="\158\032\0\0\0\0\0"})
	self:recv()
	-- self:send({flags=0x31, payload="\255\255\255\255\0\0\0\0"})
	-- self:recv()
	-- self:send({flags=0x31, payload="\110\111\105\097"})
	-- self:recv()

	return self
end

function M:disconnect ()
	if self._fd ~= nil then
		unistd.close(self._fd)
		self._fd = nil
	end
end

function M:send (t)
	if self._pending then
		error("called send whilst pending send not recv'd on")
	end

	if not t.flags then
		t.flags = 0x01
	end

	if not t.seq then
		t.seq = self._seq
		self._seq = self._seq + 1
	end

	if not t.status then
		t.status = 255
	end

	if not t.payload then
		if t.cmd == nil then
			t.cmd = 1
		end

		local reg = type(t.reg) == "string" and REG[t.reg] or t.reg
		if reg == nil then
			error("unknown reg")
		end

		if t.reglen == nil then
			t.reglen = 3
		end

		-- Request Payload: [type (1 byte)][reg (3 bytes)[reglen (2 bytes)]
		t.payload = struct.pack(">Bc3H", t.cmd, struct.pack(">I", reg):sub(2), t.reglen)
	end

	-- Ethernet: [dst (6 bytes)][src (6 bytes)][proto (2 bytes)]
	local pkt = struct.pack(">c6c6H", self._addr, self._addr_local, PROTO)

	-- Request Header: [payload len (2 bytes)][flags (1 byte)][seq (4 bytes)][status (1 byte)]
	pkt = pkt .. struct.pack(">HBIB", t.payload:len(), t.flags, t.seq, t.status) .. t.payload

	-- Padding
	pkt = pkt .. string.rep("\0", math.max(0, 64 - pkt:len()))

	assert(socket.send(self._fd, pkt) == pkt:len())

	self._pending = true
end

function M:recv ()
	if not self._pending then
		error("called recv before send")
	end

	local r = poll.rpoll(self._fd, 100)
	if r == 0 then
		return nil, "no response"
	end

	local pkt = socket.recv(self._fd, MAXSIZE)

	-- remember to filter on dst (our) macaddr as someone may have the NIC set to promisc

	self._pending = false

	return pkt
end

return M
