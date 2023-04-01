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

local iftable = {1,3,6,1,2,1,2,2,1}
local iftable_ifindex = {unpack(iftable)}
table.insert(iftable_ifindex, 1)

local ifindex
local agentx_cb = function (request)
	local response

	io.stderr:write("nyi, " .. tostring(request._hdr.type) .. "\n")

	return response
end
local session = agentx:session({name="EBM", cb=agentx_cb})

while not ifindex do
	local status, result

	status, result = session:index_allocate({["type"]=agentx.vtype.Integer, name=iftable_ifindex, flags=agentx.flags.NEW_INDEX})
	if not status then
		error(result)
	end
	if result.error ~= agentx.error.noAgentXError then
		error(result.error)
	end

	ifindex = result.varbind[1]

	local subtree = {unpack(iftable_ifindex)}
	table.insert(subtree, ifindex.data)

	status, result = session:register({range_subid=#subtree - 1, subtree=subtree, upper_bound=22})
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

local iftable_copy = {unpack(iftable)}
table.insert(iftable_copy, ifindex.data)
table.insert(iftable_copy, 0)
iftable_copy[#iftable_copy] = 1
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Integer, data = ifindex.data }
iftable_copy[#iftable_copy] = 2
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.OctetString, data = "CHEESE" }

iftable_copy[#iftable_copy] = 1
for k, v in session.mibview(iftable_copy) do
	print(k, v.type)
end

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
