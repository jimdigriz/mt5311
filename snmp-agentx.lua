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

local ax_cb = function (session, request)
	local response

	io.stderr:write("nyi, " .. tostring(request._hdr.type) .. "\n")

	return response
end
local ax_session, err = agentx:session({ name="EBM: " .. arg[2] .. "%" .. arg[1], cb=ax_cb })
if not ax_session then
	error(err)
end

local iftable = {1,3,6,1,2,1,2,2}
local iftable_ifindex = {unpack(iftable)}
table.insert(iftable_ifindex, 1)	-- ifEntry
table.insert(iftable_ifindex, 1)	-- ifIndex

local ifindex
-- local ifindex, err = ax_session:index_allocate({ ["type"]=agentx.VTYPE.Integer, name=iftable_ifindex, flags=agentx.FLAGS.NEW_INDEX })
local ifindex, err = ax_session:index_allocate({ ["type"]=agentx.VTYPE.Integer, name=iftable_ifindex, data = IFINDEX })
if not ifindex then
	error(err)
end

local status, err = assert(loadfile(dir .. "snmp-agentx-mib.lua"))(agentx, ax_session, ifindex, ebm, ebm_session)
if not status then
	error(err)
end

local fds = {
	[ax_session.fd] = { events = { IN = true } },
	[ebm_session.fd] = { events = { IN = true } }
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
		end
	end
end

ax_session:close()
ebm_session:close()
