#!/usr/bin/env lua

-- https://luaposix.github.io/luaposix/examples/packet-socket.lua.html
local socket = require "posix.sys.socket"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(arg[0]:match("^(.-/?)[^/]+.lua$") .. "struct.lua"))
end

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

local function macaddr2bytes (macaddr)
	local macaddr = {macaddr:lower():match("^(%x%x)" .. string.rep("[:-]?(%x%x)", 5) .. "$")}
	if #macaddr ~= 6 then
		io.stderr:write("invalid MAC address\n")
		os.exit(1)
	end
	for i, v in ipairs(macaddr) do
		macaddr[i] = string.char(tonumber("0x" .. v))
	end
	macaddr = table.concat(macaddr, "")
	assert(#macaddr == 6)
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
local proto = "\097\032"	-- 0x6120

-- https://stackoverflow.com/a/23596380
local little_endian = string.dump(function() end):byte(7) == 1

-- luaposix does not support AF_PACKET/SOCK_DGRAM :(
local fd = assert(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, little_endian and 0x2061 or 0x6120))
assert(socket.bind(fd, {family=socket.AF_PACKET, ifindex=socket.if_nametoindex(iface)}))
-- pkt = socket.recv(fd, 1000)
-- remember to filter on dst (our) macaddr as someone may have the NIC set to promisc
-- print(pkt)
pkt = macaddr .. iface_macaddr .. proto .. "1111"
assert(socket.send(fd, pkt) == pkt:len())
require "posix.unistd".close(fd)

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
