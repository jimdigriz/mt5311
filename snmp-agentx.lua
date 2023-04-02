#!/usr/bin/env lua

-- EBM SNMP subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local poll = require "posix.poll"

local dir = arg[0]:match("^(.-/?)[^/]+.lua$")
local status, agentx = pcall(function () return require "agentx" end)
if not status then
	agentx = assert(loadfile(dir .. "agentx.lua"))()
end
local status, ebm = pcall(function () return require "ebm" end)
if not status then
	struct = assert(loadfile(dir .. "ebm.lua"))()
end

if #arg < 2 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR\n")
	os.exit(1)
end

-- duplicate of agentx.lua
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


-- local session = ebm:session({iface=arg[1], addr=arg[2]})
-- session:send({reg='linktime'})
-- print(session:recv())

local iftable = {1,3,6,1,2,1,2,2,1}
local iftable_ifindex = {unpack(iftable)}
table.insert(iftable_ifindex, 1)

local ifindex
local agentx_cb = function (session, request)
	local response

	io.stderr:write("nyi, " .. tostring(request._hdr.type) .. "\n")

	return response
end
local session = agentx:session({name="EBM", cb=agentx_cb})
local ifindex = session:index_allocate({["type"]=agentx.VTYPE.Integer, name=iftable_ifindex, flags=agentx.FLAGS.NEW_INDEX})
if not ifindex then
	error("ifindex")
end

local iftable_copy = {unpack(iftable)}
table.insert(iftable_copy, 0)
table.insert(iftable_copy, ifindex)

local mibview_iftable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = ifindex },	-- auto-registered by index_allocate
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = arg[1] .. ".ebm" },
	[3]	= { ["type"] = agentx.VTYPE.Integer, data = 97 },
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = 1500 },
	[5]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },
	[6]	= { ["type"] = agentx.VTYPE.OctetString, data = macaddr2bytes(arg[2]) },
	[7]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },
	[8]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },
	[9]	= { ["type"] = agentx.VTYPE.TimeTicks, data = 69 },
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }
}
for i=10,20 do
	mibview_iftable_load[i] = { ["type"] = agentx.VTYPE.Counter32, data = 0 }
end
for k, v in pairs(mibview_iftable_load) do
	iftable_copy[#iftable_copy - 1] = k
	session.mibview[iftable_copy] = v
end

iftable_copy[#iftable_copy - 1] = 2
local status, result = session:register({range_subid=#iftable_copy - 1, subtree=iftable_copy, upper_bound=22})

local fds = {
	[session.fd] = { events = { IN = true } }
}
while true do
	local status, err = pcall(function() return poll.poll(fds) end)
	if not status then
		error(err)
	end
	for k, v in pairs(fds) do
		local err
		if v.revents.IN then
			if k == session.fd then
				status, err = session:process()
			else
				status, err = ebm:process()
			end
			if not status then
				error(err)
			end
			v.revents.IN = false
		elseif v.revents.HUP then
			error("nyi")
		else
			error("nyi")
		end
	end
end

session:close()
