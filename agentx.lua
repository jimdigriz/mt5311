-- SNMP AgentX Subagent
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

-- https://datatracker.ietf.org/doc/html/rfc2741

local bit32 = require "bit32"
local errno = require "posix.errno"
local fcntl = require "posix.fcntl"
local poll = require "posix.poll"
local socket = require "posix.sys.socket"
if socket.AF_PACKET == nil then error("AF_PACKET not available, did you install lua-posix 35.1 or later?") end
local unistd = require "posix.unistd"

-- https://github.com/iryont/lua-struct
local status, struct = pcall(function () return require "struct" end)
if not status then
	struct = assert(loadfile(arg[0]:match("^(.-/?)[^/]+.lua$") .. "struct.lua"))()
end

local unpack = table.unpack or _G.unpack

local HDRSIZE = 20

local FLAGS = {
	INSTANCE_REGISTRATION	= 0x01,
	NEW_INDEX		= 0x02,
	ANY_INDEX		= 0x04,
	NON_DEFAULT_CONTEXT	= 0x08,
	NETWORK_BYTE_ORDER	= 0x10
}

local PTYPE = {
	_hdr			= 0,
	Open			= 1,
	Close			= 2,
	Register		= 3,
	Unregister		= 4,
	Get			= 5,
	GetNext			= 6,
	GetBulk			= 7,
	TestSet			= 8,
	CommitSet		= 9,
	UndoSet			= 10,
	CleanupSet		= 11,
	Notify			= 12,
	Ping			= 13,
	IndexAllocate		= 14,
	IndexDeallocate		= 15,
	AddAgentCaps		= 16,
	RemoveAgentCaps		= 17,
	Response		= 18
}

local VTYPE = {
	_SearchRange		= -2,
	_VarBind		= -1,
	Integer			= 2,
	OctetString		= 4,
	Null			= 5,
	ObjectIdentifer		= 6,
	IpAddress		= 64,
	Counter32		= 65,
	Gauge32			= 66,
	TimeTicks		= 67,
	Opaque			= 68,
	Counter64		= 67,
	noSuchObject		= 128,
	noSuchInstance		= 129,
	endOfMibView		= 130
}

local ERROR = {
	noAgentXError		= 0,
	openFailed		= 256,
	notOpen			= 257,
	indexWrongType		= 258,
	indexAlreadyAllocated	= 259,
	indexNoneAvailable	= 260,
	indexNotAllocated	= 261,
	unsupportedContext	= 262,
	duplicateRegistration	= 263,
	unknownRegistration	= 264,
	unknownAgentCaps	= 265,
	parseError		= 266,
	requestDenied		= 267,
	processingError		= 268
}

local REASON = {
	other			= 1,
	parseError		= 2,
	protocolError		= 3,
	timeouts		= 4,
	shutdown		= 5,
	byManager		= 6
}

local OID = { mt = {} }
function OID.new (t)
	local o = {unpack(t)}
	setmetatable(o, OID.mt)
	return o
end
function OID.mt.__tostring (v, b)
	return "." .. table.concat(v, ".")
end
function OID.mt.__eq (a, b)
	if #a ~= #b then
		return false
	end
	for ii, vv in ipairs(a) do
		if vv ~= b[ii] then
			return false
		end
	end
	return true
end
function OID.mt.__lt (a, b)
	for i=1,math.min(#a, #b) do
		if a[i] ~= b[i] then
			return a[i] < b[i]
		end
	end
	return #a < #b
end

local MIBView = { mt = {} }
function MIBView.new ()
	local t = { k = {}, v = {} }
	setmetatable(t, MIBView.mt)
	return t
end
function MIBView.mt.__index (t, k)
	assert(#k > 0)
	local o = (getmetatable(k) == MIBView.mt) and k or OID.new(k)
	for ii, vv in ipairs(t.k) do
		if vv == o then
			return t.v[ii]
		end
	end
	return nil
end
function MIBView.mt.__newindex (t, k, v)
	assert(#k > 0)
	local o = (getmetatable(k) == MIBView.mt) and k or OID.new(k)
	for ii, vv in ipairs(t.k) do
		if not v and vv == o then
			table.remove(t.k, ii)
			table.remove(t.v, ii)
			return
		elseif vv >= o then
			table.insert(t.k, ii, o)
			table.insert(t.v, ii, v)
			return
		end
	end
	if v then
		table.insert(t.k, o)
		table.insert(t.v, v)
	end
end
function MIBView.mt.__call (t, k)
	k = k or {}
	local o = (getmetatable(k) == MIBView.mt) and k or OID.new(k)
	local i = #t.k
	for ii, vv in ipairs(t.k) do
		if vv >= o then
			i = ii - 1
			break
		end
	end
	return function ()
		if i == #t.k then return nil end
		i = i + 1
		return OID.new({unpack(t.k[i])}), t.v[i]
	end
end

local val = { enc = {}, dec = {} }

val.enc[VTYPE.ObjectIdentifer] = function (v, i)
	v = v or {}

	local prefix = 0
	if #v > 4 and v[1] == 1 and v[2] == 3 and v[3] == 6 and v[4] == 1 and v[5] < 256 then
		prefix = v[5]
		v = {unpack(v, 6)}
	end

	local include = i and 1 or 0

	return struct.pack(">BBBB" .. string.rep("I", #v), #v, prefix, include, 0, unpack(v))
end

val.dec[VTYPE.ObjectIdentifer] = function (pkt)
	local len, prefix, include, reserved = struct.unpack(">BBBB", pkt)
	pkt = pkt:sub(5)
	local v = {struct.unpack(">" .. string.rep("I", len), pkt)}
	if prefix > 0 then
		v = {1,3,6,1,prefix,unpack(v)}
	end
	return pkt:sub(1 + 4 * len), (#v > 0) and OID.new(v) or nil, include
end

val.enc[VTYPE._SearchRange] = function (t)
	return val.enc[VTYPE.ObjectIdentifer](t.start, t.include) .. val.enc[VTYPE.ObjectIdentifer](t["end"])
end

val.dec[VTYPE._SearchRange] = function (pkt)
	local vstart, include, vend
	pkt, vstart, include = val.dec[VTYPE.ObjectIdentifer](pkt)
	pkt, vend = val.dec[VTYPE.ObjectIdentifer](pkt)
	return pkt, { start = vstart, include = include, ["end"] = vend }
end

val.enc[VTYPE.OctetString] = function (v)
	v = v or ""
	local plen = (4 - (v:len() % 4)) % 4
	return struct.pack(">I", v:len()) .. v .. string.rep("\0", plen)
end

val.dec[VTYPE.OctetString] = function (pkt)
	local len = struct.unpack(">I", pkt)
	local plen = (4 - (len % 4)) % 4
	return pkt:sub(5 + len + plen), pkt:sub(5, len)
end

val.enc[VTYPE._VarBind] = function (t)
	local data
	if t.type == VTYPE.Integer or t.type == VTYPE.Counter32 or t.type == VTYPE.Gauge32 or t.type == VTYPE.TimeTicks then
		data = struct.pack(">I", t.data or 0)
	elseif t.type == VTYPE.Counter64 then
		error("nyi")
	elseif t.type == VTYPE.ObjectIdentifer then
		data = val.enc[VTYPE.ObjectIdentifer](t.data)
	elseif t.type == VTYPE.OctetString or t.type == VTYPE.IpAddress or t.type == VTYPE.Opaque then
		data = val.enc[VTYPE.OctetString](t.data)
	elseif t.type == VTYPE.Null or t.type == VTYPE.noSuchObject or t.type == VTYPE.noSuchInstance or t.type == VTYPE.endOfMibView then
		data = ""
	else
		error("nyi " .. t.type)
	end
	return struct.pack(">H", t.type) .. "\0\0" .. val.enc[VTYPE.ObjectIdentifer](t.name) .. data
end

val.dec[VTYPE._VarBind] = function (pkt)
	local vtype = struct.unpack(">H", pkt)
	pkt = pkt:sub(5)

	local name, include
	pkt, name, include = val.dec[VTYPE.ObjectIdentifer](pkt)

	local data
	if vtype == VTYPE.Integer or vtype == VTYPE.Counter32 or vtype == VTYPE.Gauge32 or vtype == VTYPE.TimeTicks then
		data = struct.unpack(">I", pkt)
		pkt = pkt:sub(5)
	elseif vtype == VTYPE.Counter64 then
		error("nyi")
	elseif vtype == VTYPE.ObjectIdentifer then
		pkt, data = val.dec[VTYPE.ObjectIdentifer](pkt)
	elseif vtype == VTYPE.OctetString or vtype == VTYPE.IpAddress or vtype == VTYPE.Opaque then
		pkt, data = val.dec[VTYPE.OctetString](pkt)
	elseif vtype == VTYPE.ObjectIdentifer then
		pkt, data = val.dec[VTYPE.ObjectIdentifer](pkt)
	elseif vtype == VTYPE.Null or vtype == VTYPE.noSuchObject or vtype == VTYPE.noSuchInstance or vtype == VTYPE.endOfMibView then
		data = nil
	else
		error("nyi " .. tostring(vtype))
	end

	return pkt, { ["type"] = vtype, name = name, data = data }
end

local pdu = { enc = {}, dec = {} }

pdu.enc_hdr = function (s, t)
	local flags = bit32.bor(t.flags or 0x00, FLAGS.NETWORK_BYTE_ORDER)
	-- RFC 2741, section 6.1.1
	local context = ""
	if s.context and
            (   t.type == PTYPE.Register
	     or t.type == PTYPE.Unregister
	     or t.type == PTYPE.AddAgentCaps
	     or t.type == PTYPE.RemoveAgentCaps
	     or t.type == PTYPE.Get
	     or t.type == PTYPE.GetNext
	     or t.type == PTYPE.GetBulk
	     or t.type == PTYPE.IndexAllocate
	     or t.type == PTYPE.IndexDeallocate
	     or t.type == PTYPE.Notify
	     or t.type == PTYPE.TestSet
	     or t.type == PTYPE.Ping) then
		flags = bit32.bor(flags, FLAGS.NON_DEFAULT_CONTEXT)
		context = val.enc[VTYPE.OctetString](s.context)
	end
	-- RFC 2741, section 6.1
	return struct.pack(">BBBBIIII", 1, t.type, flags, 0, s.sessionID or 0, s.transactionID or 0, s.packetID, t.payload:len()) .. context .. t.payload
end

pdu.dec_hdr = function (pkt)
	local version, ptype, flags, reserved, sessionID, transactionID, packetID, payload_length = struct.unpack(">BBBBIIII", pkt)
	local context
	if bit32.band(flags, FLAGS.NON_DEFAULT_CONTEXT) ~= 0 then
		pkt, context = val.dec[VTYPE.OctetString](pkt:sub(21))
		assert(pkt:len() == 0)
	end
	return {
		version		= version,
		["type"]	= ptype,
		flags		= flags,
		sessionID	= sessionID,
		transactionID	= transactionID,
		packetID	= packetID,
		payload_length	= payload_length,
		context		= context
	}
end

-- https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.1
pdu.enc[PTYPE.Open] = function (s, t)
	local deadtime = t.deadtime or 0
	local payload = struct.pack(">B", deadtime) .. "\0\0\0" .. val.enc[VTYPE.ObjectIdentifer]() .. val.enc[VTYPE.OctetString](t.name)
	return pdu.enc_hdr(s, {["type"]=PTYPE.Open, payload=payload})
end

pdu.enc[PTYPE.Close] = function (s, t)
	t = t or {}
	local reason = t.reason or REASON.other
	local payload = struct.pack(">B", reason) .. "\0\0\0"
	return pdu.enc_hdr(s, {["type"]=PTYPE.Close, payload=payload})
end

pdu.dec[PTYPE.Close] = function (pkt, res)
	local reason = struct.unpack(">B", pkt)
	res.reason = reason
	return pkt:sub(2), res
end

pdu.dec[PTYPE.Get] = function (pkt, res)
	res.sr = {}
	while pkt:len() > 0 do
		local sr
		pkt, sr = val.dec[VTYPE._SearchRange](pkt)
		table.insert(res.sr, sr)
	end
	return pkt, res
end

pdu.dec[PTYPE.GetNext] = pdu.dec[PTYPE.Get]

pdu.dec[PTYPE.GetBulk] = function (pkt, res)
	local non_repeaters, max_repetitions = struct.unpack(">HH", pkt)
	pkt = pkt:sub(5)

	res.non_repeaters = non_repeaters
	res.max_repetitions = max_repetitions

	res.sr = {}
	while pkt:len() > 0 do
		local sr
		pkt, sr = val.dec[VTYPE._SearchRange](pkt)
		table.insert(res.sr, sr)
	end

	return pkt, res
end

pdu.enc[PTYPE.Register] = function (s, t)
	local timeout = t.timeout or 0
	local priority = t.priority or 127
	local range_subid = t.range_subid or 0
	local payload = struct.pack(">BBBB", timeout, priority, range_subid, 0) .. val.enc[VTYPE.ObjectIdentifer](t.subtree)
	if range_subid > 0 then
		payload = payload .. struct.pack(">I", t.upper_bound)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.Register, payload=payload, flags=t.flags})
end

pdu.enc[PTYPE.IndexAllocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind or {}) do
		payload = payload .. val.enc[VTYPE._VarBind](v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.IndexAllocate, payload=payload, flags=t.flags})
end

pdu.enc[PTYPE.IndexDeallocate] = function (s, t)
	local payload = ""
	for i, v in ipairs(t.varbind or {}) do
		payload = payload .. val.enc[VTYPE._VarBind](v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.IndexDeallocate, payload=payload})
end

pdu.enc[PTYPE.Response] = function (s, t)
	local payload = struct.pack(">IHH", 0, t.error or ERROR.noAgentXError, t.index or 0)
	for i, v in ipairs(t.varbind or {}) do
		payload = payload .. val.enc[VTYPE._VarBind](v)
	end
	return pdu.enc_hdr(s, {["type"]=PTYPE.Response, payload=payload})
end

pdu.dec[PTYPE.Response] = function (pkt, res)
	local sysUpTime, perror, index = struct.unpack(">IHH", pkt)
	pkt = pkt:sub(9)

	res.sysUpTime = sysUpTime
	res.error = perror
	res.index = index

	res.varbind = {}
	while pkt:len() > 0 do
		local varbind
		pkt, varbind = val.dec[VTYPE._VarBind](pkt)
		table.insert(res.varbind, varbind)
	end

	return pkt, res
end

local M = { OID = OID, PTYPE = PTYPE, VTYPE = VTYPE, FLAGS = FLAGS, ERROR = ERROR, REASON = REASON }

function M:session (t)
	t = t or {}

	setmetatable({}, self)
	self.__index = self

	t.name = t.name or "Lua AgentX"
	t.path = t.path or "/var/agentx/master"
	t.deadtime = 0

	self._sessionID = nil
	self._packetID = 0
	self._requests = {}

	self.fd = assert(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0))
	local ok, err, e = socket.connect(self.fd, { family=socket.AF_UNIX, path=t.path })
	if not ok then
		self:close()
		return nil, err
	end

	-- https://github.com/luaposix/luaposix/issues/354
--	local fdflags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
--	assert(fcntl.fcntl(self.fd, fcntl.F_SETFL, bit32.bor(fdflags, fcntl.O_NONBLOCK)))

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

	local session = { sessionID=0, packetID=self._packetID }
	local status, result = self:_request(pdu.enc[PTYPE.Open](session, t))
	if not status then
		error(result)
	end
	if result.error ~= ERROR.noAgentXError then
		error("AgentX master returned error code " .. tostring(result.error))
	end

	self._sessionID = result._hdr.sessionID

	self.mibview = MIBView.new()

	return self
end

function M:close ()
	if self._sessionID ~= nil then
		local session = { sessionID=self._sessionID, packetID=self._packetID }
		local status, result = self:_request(pdu.enc[PTYPE.Close](session))
		if not status then
			error(result)
		end
		if result and result.error ~= ERROR.noAgentXError then
			return false, "AgentX master returned error code " .. tostring(result.error)
		end
		self._sessionID = nil
	end
	if self.fd ~= nil then
		unistd.close(self.fd)
		self.fd = nil
	end
	return true
end

function M:process ()
	local status, result = coroutine.resume(self._producer)
	if not status then
		if result == "closed" then
			self._sessionID = nil
			self:close()
		end
		return false, result
	end
	if not result then return true end
	if result._hdr.type == PTYPE.Response then
		local co = self._requests[result._hdr.packetID]
		self._requests[result._hdr.packetID] = nil
		coroutine.resume(co, result)
	else
		local cb = function (res)
			self:_send(pdu.enc[PTYPE.Response](result._hdr, res))
		end
		self._consumer(result, cb)
	end
	return true
end

function M:_producer_co ()
	return coroutine.create(function ()
		while true do
			local hdrpkt = ""
			while true do
				local buf, err = socket.recv(self.fd, HDRSIZE - hdrpkt:len())
				if not buf then
					if err == errno.EAGAIN then
						coroutine.yield()
					else
						error("recv() " .. err)
					end
				else
					if buf:len() == 0 then error("closed", 0) end
					hdrpkt = hdrpkt .. buf
					if hdrpkt:len() == 20 then break end
					coroutine.yield()
				end
			end

			local hdr = pdu.dec_hdr(hdrpkt)
			assert(self._sessionID == nil or hdr.sessionID == self._sessionID)

			local payload = ""
			while true do
				local buf, err = socket.recv(self.fd, hdr.payload_length - payload:len())
				if not buf then
					if err == errno.EAGAIN then
						coroutine.yield()
					else
						error("recv() " .. err)
					end
				else
					if buf:len() == 0 then error("closed", 0) end
					payload = payload .. buf
					if payload:len() == hdr.payload_length then break end
					coroutine.yield()
				end
			end

			local status, pkt, res = pcall(function () return pdu.dec[hdr.type](payload, { _hdr = hdr }) end)
			if status then
				assert(pkt:len() == 0)
				coroutine.yield(res)
			else
				io.stderr:write("pdu decode error: " .. pkt .. "\n")
				self:_send(pdu.enc[PTYPE.Response](hdr, { ["error"] = ERROR.parseError }))
				coroutine.yield()
			end
		end
	end)
end

function M:_consumer_mibview (request)
	local function mibview_get (request)
		local varbind = {}

		for i, v in ipairs(request.sr) do
			local vb = { name = v.start }
			local vv = self.mibview[v.start]
			if vv then
				vb.type = vv.type
				vb.data = vv.data
			else
				vb.type = VTYPE.noSuchInstance
				for kkk, vvv in self.mibview() do
					if #vb.name < #kkk then
						local match = true
						for j=1,#vb.name do
							if vb.name[j] ~= kkk[j] then
								match = false
								break
							end
						end
						if match then
							vb.type = VTYPE.noSuchObject
							break
						end
					end
				end
			end
			table.insert(varbind, vb)
		end

		return varbind
	end

	local function mibview_getnext (request)
		local varbind = {}

		for i, v in ipairs(request.sr) do
			local vb = {}
			local iter = self.mibview(v.start)
			local kk, vv = iter()
			if kk and v.include == 0 and kk == v.start then
				kk, vv = iter()
			end
			if kk and (not v["end"] or kk < v["end"]) then
				vb.name = kk
				vb.type = vv.type
				vb.data = vv.data
			elseif v["end"] then
				local kkk, vvv
				for kkkk, vvvv in self.mibview() do
					if kkkk >= v["end"] then break end
					if (v.include == 0 and kkkk > v.start) or (v.include == 1 and kkkk >= v.start) then
						kkk = kkkk
						vvv = vvvv
					end
				end
				if kkk then
					vb.name = kkk
					vb.type = vvv.type
					vb.data = vvv.data
				else
					vb.name = v.start
					vb.type = VTYPE.endOfMibView
				end
			else
				vb.name = v.start
				vb.type = VTYPE.endOfMibView
			end
			table.insert(varbind, vb)
			if i == request.non_repeaters then break end	-- getbulk
		end

		return varbind
	end

	local function mibview_getbulk (request, varbind)
		if request.max_repetitions == 0 then return end
		local k0 = request.sr[request.non_repeaters + 1].start
		local iter = self.mibview(k0)
		local k, v = iter()
		if k and request.include == 0 and k == k0 then
			k, v = iter()
		end
		if not k then return end
		local i = 0
		for k, v in iter() do
			table.insert(varbind, { name = k, type = v.type, data = v.data })
			i = i + 1
			if i > request.max_repetitions then break end
		end
		if i < request.max_repetitions then
			table.insert(varbind, { name = varbind[#t].name, type = VTYPE.endOfMibView })
		end
	end

	local status = false
	local response

	if request._hdr.type == PTYPE.Get then
		status = true
		varbind = mibview_get(request)
	elseif request._hdr.type == PTYPE.GetNext then
		status = true
		varbind = mibview_getnext(request)
	elseif request._hdr.type == PTYPE.GetBulk then
		status = true
		varbind = mibview_getnext(request)
		mibview_getbulk(request, varbind)
	end

	if status then
		for i, v in ipairs(varbind) do
			if type(v.data) == "function" then
				v.data = v.data(v)
			elseif type(v.data) == "thread" then
				v.data = coroutine.resume(v.data, v)
			end
		end
		response = { varbind = varbind }
	end

	return status, response
end


function M:_send (msg)
	assert(socket.send(self.fd, msg) == msg:len())
end

function M:_request (msg, cb)
	self:_send(msg)

	local status, result
	local function _cb (...)
		status = true
		result = ...
	end
	local co = cb and cb or _cb
	if type(co) == "function" then co = coroutine.create(co) end

	self._requests[self._packetID] = co
	self._packetID = self._packetID + 1

	if not cb then
		while coroutine.status(co) ~= "dead" do
			self:process()
		end
		return status, result
	end

	return co
end

function M:register (t)
	local session = { sessionID = self._sessionID, packetID = self._packetID, context = t.context }
	t.flags = bit32.bor(t.flags or 0x00, FLAGS.INSTANCE_REGISTRATION)
	return self:_request(pdu.enc[PTYPE.Register](session, t))
end

-- Net-SNMP's snmpd does not seem to provide a usable index allocation response. Though the index allocation
-- works as you would expect, the Register command seems unwilling to return duplicateRegistration making it
-- impossible to use the process described in RFC 2741, section 7.1.4.2.2 covering Index Allocation.
--
-- This means you are unable to reserve an ifIndex safely for use in IF-MIB::ifTable
--
-- For now the only safe(r) strategy is to pick a high non-conflicting number and hope it pans out okay
function M:index_allocate (t)
	if t.name then
		t = { flags = t.flags, context = t.context, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	assert(#t.varbind == 1)	-- FIXME support more than one with the auto-registration support

	local session
	local ifindex
	while not ifindex do
		session = { sessionID = self._sessionID, packetID = self._packetID, context = t.context }
		local status, result = self:_request(pdu.enc[PTYPE.IndexAllocate](session, t))
		if not status then
			error(result)
		end
		if result.error ~= ERROR.noAgentXError then
			error(result.error)
		end

		ifindex = result.varbind[1]

		local subtree = {unpack(ifindex.name)}
		table.insert(subtree, ifindex.data)

		status, result = self:register({ subtree = subtree, context = t.context })
		if not status then
			error(result)
		end
		if result.error == ERROR.duplicateRegistration then
			status, result = self:index_deallocate(session, { ["type"] = ifindex.type, name = subtree, data = ifindex.data, context = t.context })
			if not status then
				error(result)
			end
			if result.error ~= ERROR.noAgentXError then
				error(result.error)
			end
			ifindex = nil
		elseif result.error ~= ERROR.noAgentXError then
			error(result.error)
		end
	end

	local subtree = {unpack(ifindex.name)}
	table.insert(subtree, ifindex.data)
	self.mibview[subtree] = { ["type"] = ifindex.type, data = ifindex.data }

	return ifindex.data
end

function M:index_deallocate (t)
	if t.name then
		t = { flags = t.flags, context = t.context, varbind = { { ["type"] = t.type, name = t.name, data = t.data } } }
	end
	local session = { sessionID = self._sessionID, packetID = self._packetID, context = t.context }
	local status, result = self:_request(pdu.enc[PTYPE.IndexDeallocate](session, t))
	if status then
		for i, v in ipairs(t.varbind) do
			local subtree = {unpack(v.name)}
			table.insert(subtree, v.data)
			self.mibview[subtree] = nil
		end
	end
	return status, result
end

return M
