-- EBM SNMP Subagent - AgentX implementation MIBs
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local agentx, ax_session, ifindex, ebm, ebm_session, wheel = ...

local bit32 = require "bit32"

local vdsl2MIB = {1,3,6,1,2,1,10,251}

local function ebm_session_read (regs)
	local status, result = ebm_session:read(regs)
	if not status then
		error(result)
	end
	return result.data
end

---- ifTable ----

local iftableMIB = {}
iftableMIB.ifDescr = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({
			"CPE Vendor ID (and SpecInfo) [SI1,SI0,0]",
			"CPE Vendor ID [1:3]",
			"CPE Inventory Version [0:2]",
			"CPE Inventory Version [3:5]",
			"CPE Inventory Version [6:8]",
			"CPE Inventory Version [9:11]",
			"CPE Inventory Version [12:14]",
			"CPE Inventory Version [15:17]"
		})
		local ifdescr = ""
		for i, v in ipairs(result) do
			ifdescr = ifdescr .. v.raw
		end
		return ifdescr:sub(3, 3 + 3) .. " " .. ifdescr:sub(3 + 3 + 1, -3)
	end)
end
iftableMIB.ifSpeed = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateDs" })
		return result[1].int * 1000
	end)
end
iftableMIB.ifOperStatus = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "PhyStatus(?)" })
		return ((bit32.band(result[1].int, 0x00ff00) / 256) == 3) and 1 or 2	-- SHOWTIME?
	end)
end
local function linktime_wheel ()
	ebm_session:read({ "Link Time" }, coroutine.create(function(result)
		iftableMIB._linktime = result.data[1].int
		wheel[1000] = linktime_wheel
	end))
end
linktime_wheel()
wheel[1000] = linktime_wheel
iftableMIB.ifLastChange = function (request)
	return math.max(0, ax_session:sysUpTime() - (iftableMIB._linktime * 100))
end

-- RFC 5650, section 2.1.1
local mibview_iftable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = ifindex.data },			-- ifIndex: auto-registered by index_allocate
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = iftableMIB.ifDescr },		-- ifDescr
	[3]	= { ["type"] = agentx.VTYPE.Integer, data = vdsl2MIB[#vdsl2MIB] },		-- ifType
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = 1500 },				-- ifMtu
	[5]	= { ["type"] = agentx.VTYPE.Gauge32, data = iftableMIB.ifSpeed },		-- ifSpeed
	[6]	= { ["type"] = agentx.VTYPE.OctetString, data = "" },				-- ifPhysAddress
	[7]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifAdminStatus
	[8]	= { ["type"] = agentx.VTYPE.Integer, data = iftableMIB.ifOperStatus },		-- ifOperStatus
	[9]	= { ["type"] = agentx.VTYPE.TimeTicks, data = iftableMIB.ifLastChange },	-- ifLastChange
	-- see for loop below
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifOutQLen (deprecated)
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }			-- ifSpecific (deprecated)
}

local iftable = {1,3,6,1,2,1,2,2}
local iftable_entry = {unpack(iftable)}
table.insert(iftable_entry, 1)		-- ifEntry
table.insert(iftable_entry, 0)
table.insert(iftable_entry, ifindex.data)

for k, v in pairs(mibview_iftable_load) do
	iftable_entry[#iftable_entry - 1] = k
	ax_session.mibview[iftable_entry] = v
end

iftable_entry[#iftable_entry - 1] = 2
local status, result = ax_session:register({subtree=iftable_entry, range_subid=#iftable_entry - 1, upper_bound=22})
if not status then
	return false, result.error
end

---- ifXTable ----

local ifXTableMIB = {}
ifXTableMIB.ifName = function (request)
	return "ebm" .. ebm_session.addr_print .. "@" .. ebm_session.iface
end
ifXTableMIB.ifHighSpeed = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateDs" })
		return math.floor(result[1].int / 1000)
	end)
end

local mibview_ifXTable_load = {
	[1]	= { ["type"] = agentx.VTYPE.OctetString, data = ifXTableMIB.ifName },		-- ifName
	[15]	= { ["type"] = agentx.VTYPE.Gauge32, data = ifXTableMIB.ifHighSpeed },		-- ifHighSpeed
	[14]	= { ["type"] = agentx.VTYPE.Integer, data = 2 },				-- ifLinkUpDownTrapEnable (FIXME: should be enabled)
	[17]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifConnectorPresent (FIXME: poll SFP)
}

local ifXTable = {1,3,6,1,2,1,31,1,1}
local ifXTable_entry = {unpack(ifXTable)}
table.insert(ifXTable_entry, 1)			-- ifXEntry
table.insert(ifXTable_entry, 0)
table.insert(ifXTable_entry, ifindex.data)	-- ifIndex

for k, v in pairs(mibview_ifXTable_load) do
	ifXTable_entry[#ifXTable_entry - 1] = k
	ax_session.mibview[ifXTable_entry] = v
end

ifXTable_entry[#ifXTable_entry - 1] = 1
local status, result = ax_session:register({subtree=ifXTable_entry, range_subid=#ifXTable_entry - 1, upper_bound=19})
if not status then
	return false, result.error
end

---- ifStackTable ----

---- ENTITY-MIB ----

---- xdsl2LineTable ----

local xdsl2LineTableMIB = {}
xdsl2LineTableMIB.xdsl2LineStatusXtuTransSys = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusXtuTransSys" })
		return result[1].raw:sub(3, 3)
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusAttainableRateDs = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateDs" })
		return result[1].int * 1000
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusAttainableRateUs = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateUs" })
		return result[1].int * 1000
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusActProfile = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusActProfile" })
		return result[1].raw:sub(3, 3)
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusActLimitMask = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({
			"xdslVdsl2ProfilesLimit8a",
			-- "xdslVdsl2ProfilesLimit8b",
			-- "xdslVdsl2ProfilesLimit8c",
			-- "xdslVdsl2ProfilesLimit8d",
			"xdslVdsl2ProfilesLimit12a",
			-- "xdslVdsl2ProfilesLimit12b",
			"xdslVdsl2ProfilesLimit17a",
			"xdslVdsl2ProfilesLimit30a",
		})
		local bits = ""
		for i, v in ipairs(result) do
			bits = bits .. result[1].raw:sub(2, 3)
		end
		return bits
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusElectricalLength = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusElectricalLength" })
		-- https://forum.kitz.co.uk/index.php?topic=10566.0
		-- kl0 is distance at 1Mhz so by using km (EBM returns metres)
		-- it makes things easier to read (math.sqrt(1)=1 for completeness)
		return (13.81 * (result[1].int / 1000) * math.sqrt(1)) * 10
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusTrellisDs = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "Trellis (DS)" })
		return result[1].int
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusTrellisUs = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "Trellis (US)" })
		return result[1].int
	end)
end

local mibview_xdsl2LineTable_load = {
	[13]	= { ["type"] = agentx.VTYPE.Opaque, data = xdsl2LineTableMIB.xdsl2LineStatusXtuTransSys },		-- xdsl2LineStatusXtuTransSys (Issue #1)
	[20]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusAttainableRateDs },	-- xdsl2LineStatusAttainableRateDs
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusAttainableRateUs },	-- xdsl2LineStatusAttainableRateUs
	[26]	= { ["type"] = agentx.VTYPE.Opaque, data = xdsl2LineTableMIB.xdsl2LineStatusActProfile },		-- xdsl2LineStatusActProfile (Issue #1)
	[26]	= { ["type"] = agentx.VTYPE.Opaque, data = xdsl2LineTableMIB.xdsl2LineStatusActLimitMask },		-- xdsl2LineStatusActLimitMask (Issue #1)
	[31]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusElectricalLength },	-- xdsl2LineStatusElectricalLength
	[36]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineTableMIB.xdsl2LineStatusTrellisDs },		-- xdsl2LineStatusTrellisDs
	[37]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineTableMIB.xdsl2LineStatusTrellisUs },		-- xdsl2LineStatusTrellisUs
}

local xdsl2LineTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2LineTable_entry, 1)			-- xdsl2Objects
table.insert(xdsl2LineTable_entry, 1)			-- xdsl2Line
table.insert(xdsl2LineTable_entry, 1)			-- xdsl2LineTable
table.insert(xdsl2LineTable_entry, 1)			-- xdsl2LineEntry
table.insert(xdsl2LineTable_entry, 0)
table.insert(xdsl2LineTable_entry, ifindex.data)	-- ifIndex

for k, v in pairs(mibview_xdsl2LineTable_load) do
	xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = k
	ax_session.mibview[xdsl2LineTable_entry] = v
end

xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = 1
local status, result = ax_session:register({subtree=xdsl2LineTable_entry, range_subid=#xdsl2LineTable_entry - 1, upper_bound=38})
if not status then
	return false, result.error
end

---- xdsl2LineBandTable ----

local xdsl2LineBandTableMIB = {}
xdsl2LineBandTableMIB.xdsl2LineBand = function (request)
	return request.name[#request.name]
end
xdsl2LineBandTableMIB._xdsl2LineBandStatus = function (request, name)
	local xdsl2LineBand = xdsl2LineBandTableMIB.xdsl2LineBand(request)
	local bands = {}
	if xdsl2LineBand == 1 or xdsl2LineBand == 3 then
		table.insert(bands, name .. " US0")
	end
	if xdsl2LineBand == 1 or xdsl2LineBand == 5 then
		table.insert(bands, name .. " US1")
	end
	if xdsl2LineBand == 1 or xdsl2LineBand == 7 then
		table.insert(bands, name .. " US2")
	end
	if xdsl2LineBand == 1 or xdsl2LineBand == 9 then
		table.insert(bands, name .. " US3")
	end
	if xdsl2LineBand == 1 or xdsl2LineBand == 11 then
		table.insert(bands, name .. " US4")
	end
	if xdsl2LineBand == 2 or xdsl2LineBand == 4 then
		table.insert(bands, name .. " DS1")
	end
	if xdsl2LineBand == 2 or xdsl2LineBand == 6 then
		table.insert(bands, name .. " DS2")
	end
	if xdsl2LineBand == 2 or xdsl2LineBand == 8 then
		table.insert(bands, name .. " DS3")
	end
	if xdsl2LineBand == 2 or xdsl2LineBand == 10 then
		table.insert(bands, name .. " DS4")
	end
	-- EBM is 24bit so limit is 0x7ffffe and not 0x7ffffffe
	return coroutine.create(function ()
		local result = ebm_session_read(bands)

		if #bands == 1 then
			return result[1].int + ((result[1].int < 0x7ffffe) and 0 or (0x7ffffffe - 0x7ffffe))
		end

		local value = 0
		for i, v in ipairs(result) do
			if v.int < 0x7ffffe then
				value = value + v.int
			end
		end
		return math.floor(value / #result)
	end)
end
xdsl2LineBandTableMIB.xdsl2LineBandStatusLnAtten = function (request)
	return xdsl2LineBandTableMIB._xdsl2LineBandStatus(request, "Line Attenuation")
end
xdsl2LineBandTableMIB.xdsl2LineBandStatusSigAtten = function (request)
	return xdsl2LineBandTableMIB._xdsl2LineBandStatus(request, "Signal Attenuation")
end
xdsl2LineBandTableMIB.xdsl2LineBandStatusSnrMargin = function (request)
	return xdsl2LineBandTableMIB._xdsl2LineBandStatus(request, "SNR Margin")
end

local mibview_xdsl2LineBandTable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineBandTableMIB.xdsl2LineBand },			-- xdsl2LineBand (not-accessible)
	[2]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineBandTableMIB.xdsl2LineBandStatusLnAtten },		-- xdsl2LineBandStatusLnAtten
	[3]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineBandTableMIB.xdsl2LineBandStatusSigAtten },	-- xdsl2LineBandStatusSigAtten
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineBandTableMIB.xdsl2LineBandStatusSnrMargin },	-- xdsl2LineBandStatusSnrMargin
}

local xdsl2LineBandTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2LineBandTable_entry, 1)		-- xdsl2Objects
table.insert(xdsl2LineBandTable_entry, 1)		-- xdsl2Line
table.insert(xdsl2LineBandTable_entry, 2)		-- xdsl2LineBandTable
table.insert(xdsl2LineBandTable_entry, 1)		-- xdsl2LineBandEntry
table.insert(xdsl2LineBandTable_entry, 0)
table.insert(xdsl2LineBandTable_entry, ifindex.data)	-- ifIndex
table.insert(xdsl2LineBandTable_entry, 0)		-- xdsl2LineBand

for k, v in pairs(mibview_xdsl2LineBandTable_load) do
	xdsl2LineBandTable_entry[#xdsl2LineBandTable_entry - 2] = k
	for i=1,11 do
		xdsl2LineBandTable_entry[#xdsl2LineBandTable_entry] = i
		ax_session.mibview[xdsl2LineBandTable_entry] = v
	end

	-- multi-index tables we need to register each entry as registering at the lowest subid does not work
	xdsl2LineBandTable_entry[#xdsl2LineBandTable_entry] = 1
	local status, result = ax_session:register({subtree=xdsl2LineBandTable_entry, range_subid=#xdsl2LineBandTable_entry, upper_bound=11})
	if not status then
		return false, result.error
	end
end

----

return true
