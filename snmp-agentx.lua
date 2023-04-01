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
local agentx_cb = function (session, request)
	local response

	if request._hdr.type == agentx.ptype.Get then
print("HERE0")
		response = { varbind = {} }
		for i, v in ipairs(request.sr) do
			local vb = { name = v.start }
			local vv = session.mibview[v.start]
			if vv then
				vb.type = vv.type
				vb.data = vv.data
			else
				vb.type = agentx.vtype.noSuchInstance
				for kkk, vvv in session.mibview() do
					if #vb.name < #kkk then
						local match = true
						for j=1,#vb.name do
							if vb.name[j] ~= kkk[j] then
								match = false
								break
							end
						end
						if match then
							vb.type = agentx.vtype.noSuchObject
							break
						end
					end
				end
			end
			table.insert(response.varbind, vb)
		end
	elseif request._hdr.type == agentx.ptype.GetNext then
		response = { varbind = {} }
		for i, v in ipairs(request.sr) do
			local vb = {}
			local iter = session.mibview(v.start)
			local kk, vv = iter()
			if kk and v.include == 0 and kk == v.start then
				kk, vv = iter()
			end
			if kk and (not v["end"] or kk < v["end"]) then
				vb.name = kk
				vb.type = vv.type
				vb.data = vv.data
print("HERE1", v.include, v.start, v["end"], vb.name, vb.type, vb.data)
			elseif v["end"] then
				local kkk, vvv
				for kkkk, vvvv in session.mibview() do
					if kkkk >= v["end"] then break end
					kkk = kkkk
					vvv = vvvv
				end
				vb.name = kkk
				vb.type = vvv.type
				vb.data = vvv.data
print("HERE2", v.include, v.start, v["end"], vb.name, vb.type, vb.data)
			else
print("HERE3", v.include, v.start, v["end"], kk)
				vb.name = v.start
				vb.type = agentx.vtype.endOfMibView
			end
			table.insert(response.varbind, vb)
		end
	elseif request._hdr.type == agentx.ptype.GetBulk then
		error("nyi")
	else
		io.stderr:write("nyi, " .. tostring(request._hdr.type) .. "\n")
	end

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
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.OctetString, data = arg[1] .. ".ebm" }
iftable_copy[#iftable_copy] = 3
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Integer, data = 97 }
iftable_copy[#iftable_copy] = 4
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Integer, data = 1500 }
iftable_copy[#iftable_copy] = 5
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Gauge32, data = 0 }
iftable_copy[#iftable_copy] = 6
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.OctetString, data = arg[2] }
iftable_copy[#iftable_copy] = 7
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Integer, data = 1 }
iftable_copy[#iftable_copy] = 8
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Integer, data = 1 }
iftable_copy[#iftable_copy] = 9
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.TimeTicks, data = 69 }
for i=10,20 do
	iftable_copy[#iftable_copy] = i
	session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Counter32, data = 0 }
end
iftable_copy[#iftable_copy] = 21
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.Gauge32, data = 0 }
iftable_copy[#iftable_copy] = 22
session.mibview[iftable_copy] = { ["type"] = agentx.vtype.ObjectIdentifer, data = {0,0} }

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
