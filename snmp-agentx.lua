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

-- local session = ebm:session({iface=arg[1], addr=arg[2]})
-- session:send({reg='linktime'})
-- print(session:recv())

local iftable_ifindex = {1,3,6,1,2,1,2,2,1,1}
local session = agentx:session({name="EBM"})
local ifindex
while not ifindex do
	local status, result

	status, result = session:index_allocate({["type"]=agentx.type.Integer, name=iftable_ifindex, flags=agentx.flags.NEW_INDEX})
	if not status then
		error(result)
	end
	if result.error ~= agentx.error.noAgentXError then
		error(result.error)
	end

	ifindex = result.varbind[1]

	local iftable = {unpack(iftable_ifindex)}
	table.insert(iftable, ifindex.data)

	status, result = session:register({range_subid=#iftable - 1, subtree=iftable, upper_bound=22})
	if not status then
		error(result)
	end
	if result.err == agentx.error.duplicateRegistration then
		status, result = session:index_deallocate(ifindex)
		if not status then
			error(result)
		end
		if result.error ~= agentx.error.noAgentXError then
			error(result.error)
		end
		ifindex = nil
	elseif result.error ~= agentx.error.noAgentXError then
		error(result.error)
	end
end

local fds = {
	[session.fd] = { events = { IN = true } }
}
while poll.poll(fds) do
	for k, v in pairs(fds) do
		if v.revents.IN then
			if k == session.fd then
				session:next()
			else
				ebm:next()
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
