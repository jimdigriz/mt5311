#!/usr/bin/env lua

-- https://luaposix.github.io/luaposix/examples/packet-socket.lua.html
local socket = require "posix.sys.socket"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(arg[0]:match("^(.-/?)[^/]+.lua$") .. "struct.lua"))
end

local PROTO = 0x6120
local MAXSIZE = 300
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

if #arg < 2 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR [ -g OID | -n OID | -s OID TYPE VALUE ]\n")
	os.exit(1)
end

local iface = arg[1]
-- luaposix does not support ioctl(fd, SIOCGIFHWADDR, &s))
local iface_macaddr_f = io.open("/sys/class/net/" .. iface .. "/address")
if not iface_macaddr_f then
	io.stderr:write("invalid IFACE\n")
	os.exit(1)
end
local iface_macaddr = macaddr2bytes(iface_macaddr_f:read())
iface_macaddr_f:close()

local macaddr = macaddr2bytes(arg[2])

-- luaposix does not support AF_PACKET/SOCK_DGRAM :(
local fd = assert(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(PROTO)))
assert(socket.bind(fd, {family=socket.AF_PACKET, ifindex=socket.if_nametoindex(iface)}))
-- FIXME do handshake with SFP (port 1-4?)

local seq = 1

local function send (t)
	-- Ethernet: [dst (6 bytes)][src (6 bytes)][proto (2 bytes)]
	local pkt = struct.pack(">c6c6H", macaddr, iface_macaddr, PROTO)

	-- Request Payload: [type (1 byte)][reg (3 bytes)[reglen (2 bytes)]
	local payload = struct.pack(">Bc3H", 1, struct.pack(">I", t.reg):sub(2), 3)

	-- Request Header: [payload len (2 bytes)][flags (1 byte)][seq (4 bytes)][status (1 byte)]
	pkt = pkt .. struct.pack(">HBIB", payload:len(), tonumber("00000001", 2), seq, 255) .. payload

	-- Padding
	pkt = pkt .. string.rep("\0", math.max(0, 64 - pkt:len()))

	assert(socket.send(fd, pkt) == pkt:len())

	seq = seq + 1
end

local function recv ()
	local pkt = socket.recv(fd, MAXSIZE)
	-- remember to filter on dst (our) macaddr as someone may have the NIC set to promisc
	return pkt
end

send({reg=REG.linktime})
print(recv())

-- integer, gauge, counter, timeticks, ipaddress, objectid, or string
local function do_get(oid)
	io.stdout:write("NONE\n")
end

-- integer, gauge, counter, timeticks, ipaddress, objectid, or string
local function do_getnext(oid)
	io.stdout:write("NONE\n")
end

-- not-writable, wrong-type, wrong-length, wrong-value or inconsistent-value
local function do_set(oid, type, value)
	io.stdout:write("not-writable\n")
end

if arg[#arg - 1] == "-g" then
	do_get(arg[#arg])
elseif arg[#arg - 1] == "-n" then
	do_getnext(arg[#arg])
elseif arg[#arg - 3] == "-s" then
	do_set(arg[#arg - 2], arg[#arg - 1], arg[#arg])
else
	io.stdout:setvbuf("line")

	while true do
		local cmd = io.stdin:read()

		if not cmd or cmd == "" then
			break
		elseif cmd == "PING" then
			io.stdout:write("PONG\n")
		else
			local oid = io.stdin:read()
			if cmd == "get" then
				do_get(oid)
			elseif cmd == "getnext" then
				do_getnext(oid)
			elseif cmd == "set" then
				local type, value = io.stdin:read():match("^([^%s]+)%s+([^%s]+)$")
				do_set(oid, type, value)
			end
		end
	end
end

require "posix.unistd".close(fd)
