-- EBM Protocol
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://luaposix.github.io/luaposix/examples/packet-socket.lua.html
local socket = require "posix.sys.socket"
local unistd = require "posix.unistd"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(arg[0]:match("^(.-/?)[^/]+.lua$") .. "struct.lua"))()
end

local PROTO = 0x6120
local MAXSIZE = 1500 - 14
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
		error("invalid MAC address '" .. v .. "'")
	end
	for i, v in ipairs(macaddr) do
		macaddr[i] = string.char(tonumber(v, 16))
	end
	macaddr = table.concat(macaddr, "")
	return macaddr
end

local ebm = {}

function ebm:connect (t)
	setmetatable({}, self)
	self.__index = self

	self._iface = t.iface

	-- luaposix does not support ioctl(fd, SIOCGIFHWADDR, &s))
	local macaddr = io.open("/sys/class/net/" .. self._iface .. "/address")
	if not macaddr then
		error("invalid iface\n")
	end
	self._addr_local = macaddr2bytes(macaddr:read())
	macaddr:close()

	self._addr = macaddr2bytes(t.addr)

	self._seq = 1

	-- luaposix does not support AF_PACKET/SOCK_DGRAM :(
	self._fd = assert(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(PROTO)))
	assert(socket.bind(self._fd, {family=socket.AF_PACKET, ifindex=socket.if_nametoindex(t.iface)}))

	return self
end

function ebm:disconnect ()
	unistd.close(self._fd)
	self._fd = nil
end

function ebm:send (t)
	local reg = type(t.reg) == "number" and t.reg or REG[t.reg]
	if reg == nil then
		error("unknown reg")
	end

	-- Ethernet: [dst (6 bytes)][src (6 bytes)][proto (2 bytes)]
	local pkt = struct.pack(">c6c6H", self._addr, self._addr_local, PROTO)

	-- Request Payload: [type (1 byte)][reg (3 bytes)[reglen (2 bytes)]
	local payload = struct.pack(">Bc3H", 1, struct.pack(">I", t.reg):sub(2), 3)

	-- Request Header: [payload len (2 bytes)][flags (1 byte)][seq (4 bytes)][status (1 byte)]
	pkt = pkt .. struct.pack(">HBIB", payload:len(), tonumber("00000001", 2), self._seq, 255) .. payload

	-- Padding
	pkt = pkt .. string.rep("\0", math.max(0, 64 - pkt:len()))

	assert(socket.send(self._fd, pkt) == pkt:len())

	self._seq = self._seq + 1
end

function ebm:recv ()
	local pkt = socket.recv(self.fd, MAXSIZE)
	-- remember to filter on dst (our) macaddr as someone may have the NIC set to promisc
	return pkt
end

return ebm
