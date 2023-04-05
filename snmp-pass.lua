#!/usr/bin/env lua

-- EBM SNMP Agent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local dir = arg[0]:match("^(.-/?)[^/]+.lua$")
-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(dir .. "struct.lua"))()
end
local status, ebm = pcall(function () return require "ebm" end)
if not status then
	ebm = assert(loadfile(dir .. "ebm.lua"))()
end

if #arg < 2 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR [ -g OID | -n OID | -s OID TYPE VALUE ]\n")
	os.exit(1)
end

local session, err = ebm:session({iface=arg[1], addr=arg[2]})
if err then
	error(err)
end

session:send({reg='linktime'})
local pkt, err = session:recv()
if not pkt then
	error(err)
end
local linktime = struct.unpack(">I", "\0" .. pkt:sub(9, 9 + 3))
print(linktime)
os.exit(0)

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
