#!/usr/bin/env lua

-- EBM Single Shot Query
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://gist.github.com/yi/01e3ab762838d567e65d
function string.tohex (str)
	return (str:gsub(".", function (c)
		return string.format("%02X", string.byte(c))
	end)):lower()
end

local dir = arg[0]:match("^(.-/?)[^/]+.lua$")
local status, ebm = pcall(function () return require "ebm" end)
if not status then
	ebm = assert(loadfile(dir .. "ebm.lua"))()
end

if #arg < 3 then
	io.stderr:write("Usage: " .. arg[0] .. " IFACE MACADDR REG ...\n")
	os.exit(1)
end

local ebm_session = ebm:session({iface=arg[1], addr=arg[2]})
if not ebm_session then
	error(err)
end

local regs = {unpack(arg, 3)}
for i, v in ipairs(regs) do
	local n = tonumber(v)
	if n then
		regs[i] = n
	end
end

local status, result = ebm_session:read(regs)
if not status then
	error(result)
end

ebm_session:close()

print("reg", "hex", "int")
for i, v in ipairs(result.data) do
	print(arg[2 + i], v.raw:tohex(), v.int)
end
