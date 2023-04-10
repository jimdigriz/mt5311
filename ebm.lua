-- EBM Protocol
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local bit32 = require "bit32"
local clock_gettime = require"posix".clock_gettime
local socket = require "posix.sys.socket"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
local time = require "posix.time"
local unistd = require "posix.unistd"

local dir = arg[0]:match("^(.-/?)[^/]+.lua$")

-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(dir .. "struct.lua"))()
end

local register, register_inv = assert(loadfile(dir .. "register.lua"))(arg)

local PROTO = 0x6120
local MAXSIZE = 1500 - 14
local SEQ = {
	HELLO_CLIENT	= 0x6c360000,
	HELLO_SERVER	= 0x6c364556
}

-- https://stackoverflow.com/a/23596380
local little_endian = string.dump(function() end):byte(7) == 1

local function htons (v)
	if little_endian then
		v = struct.unpack("H", struct.pack(">H", v))
	end
	return v
end

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

local M = {}

function M:session (t)
	t = t or {}

	if t.iface == nil then
		error("missing 'iface' parameter")
	end
	if t.addr == nil then
		error("missing 'addr' parameter")
	end

	setmetatable({}, self)
	self.__index = self

	self.iface = t.iface

	-- luaposix does not support ioctl(fd, SIOCGIFHWADDR, &s))
	local macaddr = io.open("/sys/class/net/" .. self.iface .. "/address")
	if not macaddr then
		return nil, "invalid iface"
	end
	self.addr_local = macaddr2bytes(macaddr:read())
	assert(self.addr_local)
	macaddr:close()

	self.addr = macaddr2bytes(t.addr)
	if not self.addr then
		return nil, "invalid MAC address"
	end

	-- luaposix does not support AF_PACKET/SOCK_DGRAM :(
	self.fd = assert(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(PROTO)))
	assert(socket.bind(self.fd, {family=socket.AF_PACKET, ifindex=socket.if_nametoindex(t.iface)}))

	-- https://github.com/luaposix/luaposix/issues/354
--	local fdflags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
--	assert(fcntl.fcntl(self.fd, fcntl.F_SETFL, bit32.bor(fdflags, fcntl.O_NONBLOCK)))

	self._requestID = 0
	self._requests = {}

	self._producer = self:_producer_co()
	self._consumer = function (result, cb)
		local status, response = self:_consumer_mibview(result)
		if not status then
			if type(t.cb) == "function" then
				status, response = pcall(function() return t.cb(result) end)
			elseif type(t.cb) == "thread" then
				status, response = coroutine.resume(t.cb, result)
			end
		end
		if status and type(response) == "table" then
			cb(response)
		else
			if not status then
				io.stderr:write("consumer error: " .. response .. "\n")
			end
			cb({ ["error"] = ERROR.processingError })
		end
	end

	-- handshake
	-- TODO check responses
	local status, result = self:_request({ requestID=SEQ.HELLO_CLIENT, status=0 }, "\158\032\0\0\0\0\0")
	if not status then
		error(result)
	end
	local status, result = self:_request({ flags = 0x31 }, "\255\255\255\255\0\0\0\0")
	if not status then
		error(result)
	end
	local status, result = self:_request({ flags = 0x31 }, "\110\111\105\097")
	if not status then
		error(result)
	end

	return self
end

function M:close ()
	if self.fd ~= nil then
		unistd.close(self.fd)
		self.fd = nil
	end
	return true
end

function M:process ()
	local status, result = coroutine.resume(self._producer)
	if not status then
		return false, result
	end
	if not result then return true end
	if bit32.band(result.flags, 0xf) == 1 then	-- is a request
		local requestID = result.requestID == SEQ.HELLO_SERVER and 0 or result.requestID
		local co = self._requests[requestID].co
		self._requests[requestID] = nil
		coroutine.resume(co, result)
	else
		error("nyi")
	end
	return true
end

function M:_producer_co ()
	return coroutine.create(function ()
		while true do
			local pkt, err = socket.recv(self.fd, MAXSIZE)
			if not pkt then
				if err == errno.EAGAIN then
					coroutine.yield()
				else
					error("recv() " .. err)
				end
			end

			-- filter that dst macaddr is us incase the NIC is set to promisc mode
			if pkt:sub(1, 6) ~= self.addr_local then
				coroutine.yield()
			end

			-- trim ethernet header
			pkt = pkt:sub(15)

			local res = { data = {} }
			res.plen, res.flags, res.requestID, res.status = struct.unpack(">HBIB", pkt)
			pkt = pkt:sub(1, 9)

			if bit32.band(res.flags, 0xf) == 1 then	-- is a request
				res.plen = res.plen - 6
			end

			for i=1,res.plen,3 do
				local data = pkt:sub(i, i + 3)
				table.insert(res.data, {
					[1] = data,
					int = struct.unpack(">I", "\0" .. data)
				})
			end

			coroutine.yield(res)
		end
	end)
end

function M:_request (s, t, cb)
	local flags = s.flags or 0x01
	local requestID = s.requestID or self._requestID
	local status = s.status or 255

	local payload
	if type(t) == "string" then
		payload = t
	else
		payload = ""
		for i, v in ipairs(t) do
			local cmd = v.cmd or 1

			local reg = type(v.reg) == "string" and register_inv[v.reg] or v.reg
			if reg == nil then
				error("unknown reg")
			end

			local reglen = v.reglen or 3

			-- Request Payload: [type (1 byte)][reg (3 bytes)[reglen (2 bytes)]
			payload = payload .. struct.pack(">Bc3H", cmd, struct.pack(">I", reg):sub(2), reglen)
		end
	end

	-- Ethernet: [dst (6 bytes)][src (6 bytes)][proto (2 bytes)]
	local pkt = struct.pack(">c6c6H", self.addr, self.addr_local, PROTO)

	-- Request Header: [payload len (2 bytes)][flags (1 byte)][seq (4 bytes)][status (1 byte)]
	pkt = pkt .. struct.pack(">HBIB", payload:len(), flags, requestID, status) .. payload

	-- Padding
	pkt = pkt .. string.rep("\0", math.max(0, 64 - pkt:len()))

	assert(socket.send(self.fd, pkt) == pkt:len())

	local status, result
	local function _cb (...)
		status = true
		result = ...
	end
	local co = cb and cb or _cb
	if type(co) == "function" then co = coroutine.create(co) end

	self._requests[self._requestID] = {
		ts = {clock_gettime(time.CLOCK_MONOTONIC)},
		co = co
	}
	self._requestID = self._requestID + 1

	if not cb then
		while coroutine.status(co) ~= "dead" do
			self:process()
		end
		return status, result
	end

	return co
end

return M
