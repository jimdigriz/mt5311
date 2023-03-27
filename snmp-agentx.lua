#!/usr/bin/env lua

-- EBM SNMP subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local dir = arg[0]:match("^(.-/?)[^/]+.lua$")

local status, agentx = pcall(function () return require "agentx" end)
if not status then
	struct = assert(loadfile(dir .. "agentx.lua"))()
end
local status, ebm = pcall(function () return require "ebm" end)
if not status then
	struct = assert(loadfile(dir .. "ebm.lua"))()
end

if #arg < 2 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR\n")
	os.exit(1)
end

local session = agentx:session()

-- local session = ebm:connect({iface=arg[1], addr=arg[2]})
-- session:send({reg='linktime'})
-- print(session:recv())
