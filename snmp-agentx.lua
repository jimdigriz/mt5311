#!/usr/bin/env lua

-- EBM SNMP Subagent - AgentX implementation
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local clock_gettime = require"posix".clock_gettime
local poll = require "posix.poll"
local time = require "posix.time"

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

-- see issue #2
local IFINDEX = os.getenv("IFINDEX")
if not IFINDEX then
	math.randomseed(os.time())
	IFINDEX = 10000 + math.random(10000)
end

-- timer wheel with millisecond resolution
local Wheel = { mt = {} }
function Wheel.new ()
	local w = { _k = {}, _v = {} }
	setmetatable(w, Wheel.mt)

	rawset(w, '_now', function ()
		local n = {clock_gettime(time.CLOCK_MONOTONIC)}
		return (n[1] * 1000) + math.floor((n[2] / 1000000))
	end)
	rawset(w, 'next', function ()
		return (#w._k > 0) and math.max(0, w._k[1] - w._now()) or nil
	end)
	rawset(w, 'fire', function ()
		local t = w._now()
		for i=#w._k,1,-1 do
			if w._k[i] > t then
				break
			end
			if type(w._v[i]) == "function" then
				pcall(function() return w._v[i]() end)
			elseif type(w._v[i]) == "thread" then
				coroutine.resume(w._v[i])
			end
			table.remove(w._k, i)
			table.remove(w._v, i)
		end
	end)

	return w
end
function Wheel.mt.__newindex (w, k, v)
	-- if less than a year, assume relative to now
	if k < 31536000000 then
		k = k + w._now()
	end

	if #w._k == 0 then
		table.insert(w._k, k)
		table.insert(w._v, v)
	else
		for wi, wv in ipairs(w._k) do
			if k <= kk then
				table.insert(w._k, i, k)
				table.insert(w._v, i, v)
				break
			end
		end
	end
end

local wheel = Wheel.new()

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

local status, err = assert(loadfile(dir .. "snmp-agentx-mib.lua"))(agentx, ax_session, ifindex, ebm, ebm_session, wheel)
if not status then
	error(err)
end

local fds = {
	[ax_session.fd] = { events = { IN = true } },
	[ebm_session.fd] = { events = { IN = true } }
}
while true do
	local status, ret = pcall(function() return poll.poll(fds, wheel.next() or -1) end)
	if not status then
		error(ret)
	end
	if ret == 0 then
		wheel.fire()
	end
	for k, v in pairs(fds) do
		if v.revents then
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
end

ax_session:close()
ebm_session:close()
