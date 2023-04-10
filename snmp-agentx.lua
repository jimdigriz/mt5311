#!/usr/bin/env lua

-- EBM SNMP Subagent - AgentX implementation
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
	ebm = assert(loadfile(dir .. "ebm.lua"))()
end

if #arg < 2 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR\n")
	os.exit(1)
end

-- see comment in agentx.lua:index_allocate
local IFINDEX = os.getenv("IFINDEX")
if not IFINDEX then
	math.randomseed(os.time())
	IFINDEX = 10000 + math.random(10000)
end

local ebm_session = ebm:session({iface=arg[1], addr=arg[2]})
if not ebm_session then
	error(err)
end

local iftable = {1,3,6,1,2,1,2,2}
local vdsl2MIB = {1,3,6,1,2,1,10,251}

local iftable_ifindex = {unpack(iftable)}
table.insert(iftable_ifindex, 1)	-- ifEntry
table.insert(iftable_ifindex, 1)	-- ifIndex

local ifindex
local ax_cb = function (session, request)
	local response

	io.stderr:write("nyi, " .. tostring(request._hdr.type) .. "\n")

	return response
end
local ax_session, err = agentx:session({ name="EBM", cb=ax_cb })
if not ax_session then
	error(err)
end

-- local ifindex, err = ax_session:index_allocate({ ["type"]=agentx.VTYPE.Integer, name=iftable_ifindex, flags=agentx.FLAGS.NEW_INDEX })
local ifindex, err = ax_session:index_allocate({ ["type"]=agentx.VTYPE.Integer, name=iftable_ifindex, data = IFINDEX })
if not ifindex then
	error(err)
end

local iftable_entry = {unpack(iftable)}
table.insert(iftable_entry, 1)		-- ifEntry
table.insert(iftable_entry, 0)
table.insert(iftable_entry, ifindex.data)

-- RFC 5650, section 2.1.1
local mibview_iftable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = ifindex.data },			-- ifIndex: auto-registered by index_allocate
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = ebm_session.iface .. ".ebm" },	-- ifDescr
	[3]	= { ["type"] = agentx.VTYPE.Integer, data = vdsl2MIB[#vdsl2MIB] },		-- ifType
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = 1500 },				-- ifMtu
	[5]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifSpeed
	[6]	= { ["type"] = agentx.VTYPE.OctetString, data = ebm_session.addr },		-- ifPhysAddress
	[7]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifAdminStatus
	[8]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifOperStatus
	[9]	= { ["type"] = agentx.VTYPE.TimeTicks, data = 69 },				-- ifLastChange
	-- see for loop below
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifOutQLen (deprecated)
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }			-- ifSpecific (deprecated)
}
-- ifInOctets, ifInUcastPkts, ifInNUcastPkts (deprecated), ifInDiscards, ifInErrors, ifInUnknownProtos, ifOutOctets, ifOutUcastPkts, ifOutNUcastPkts (deprecated), ifOutDiscards, ifOutErrors
for i=10,20 do
	mibview_iftable_load[i] = { ["type"] = agentx.VTYPE.Counter32, data = 0 }
end
for k, v in pairs(mibview_iftable_load) do
	iftable_entry[#iftable_entry - 1] = k
	ax_session.mibview[iftable_entry] = v
end

iftable_entry[#iftable_entry - 1] = 2
local status, result = ax_session:register({subtree=iftable_entry, range_subid=#iftable_entry - 1, upper_bound=22})

-- TODO register ifStack too


local fds = {
	[ax_session.fd] = { events = { IN = true } }
}
while true do
	local status, err = pcall(function() return poll.poll(fds) end)
	if not status then
		error(err)
	end
	for k, v in pairs(fds) do
		local err
		if v.revents.IN then
			if k == ax_session.fd then
				status, err = ax_session:process()
			else
				status, err = ebm_session:process()
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

ax_session:close()
ebm_session:close()
