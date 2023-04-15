-- EBM SNMP Subagent - AgentX implementation MIBs
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local agentx, ax_session, ifIndex, ebm, ebm_session, wheel = ...

local bit32 = require "bit32"

local vdsl2MIB = {1,3,6,1,2,1,10,251}

local function ebm_session_read (regs)
	local status, result = ebm_session:read(regs)
	if not status then
		error(result)
	end
	return result.data
end

---- IF-MIB::ifTable ----

local ifTableMIB = {}
ifTableMIB.ifDescr = function (request)
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
ifTableMIB.ifSpeed = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateDs" })
		return result[1].int * 1000
	end)
end
ifTableMIB._ifOperStatus = 4
ifTableMIB.ifOperStatus = function (request)
	return ifTableMIB._ifOperStatus
end
ifTableMIB._ifLastChange = 0
ifTableMIB.ifLastChange = function (request)
	return ifTableMIB._ifLastChange
end
local function ifTable_wheel ()
	ebm_session:read({ "PhyStatus(?)", "Link Time" }, coroutine.create(function(result)
		local sysUpTime = ax_session:sysUpTime()

		local ifOperStatus = ((bit32.band(result.data[1].int, 0x00ff00) / 256) == 3) and 1 or 2
		if ifTableMIB._ifOperStatus ~= ifOperStatus then
			ifTableMIB._ifOperStatus = ifOperStatus
			ifTableMIB._ifLastChange = sysUpTime

			-- use Link Time (has last value when down) to check we have not missed anything
			if ifOperStatus == 1 then
				local LinkUpTime = math.max(0, sysUpTime - (result.data[2].int * 100))
				-- the slip time is because we are polling a second resolution timer
				if (LinkUpTime + 100) < ifTableMIB._ifLastChange then
					ifTableMIB._ifLastChange = LinkUpTime
				end
			end
		end

		wheel[1000] = ifTable_wheel
	end))
end
ifTable_wheel()

local mibview_ifTable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = ifIndex.data },			-- ifIndex: auto-registered by index_allocate
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = ifTableMIB.ifDescr },		-- ifDescr
	[3]	= { ["type"] = agentx.VTYPE.Integer, data = vdsl2MIB[#vdsl2MIB] },		-- ifType
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = 1500 },				-- ifMtu
	[5]	= { ["type"] = agentx.VTYPE.Gauge32, data = ifTableMIB.ifSpeed },		-- ifSpeed
	[6]	= { ["type"] = agentx.VTYPE.OctetString, data = "" },				-- ifPhysAddress
	[7]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifAdminStatus
	[8]	= { ["type"] = agentx.VTYPE.Integer, data = ifTableMIB.ifOperStatus },		-- ifOperStatus
	[9]	= { ["type"] = agentx.VTYPE.TimeTicks, data = ifTableMIB.ifLastChange },	-- ifLastChange
	-- see for loop below
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifOutQLen (deprecated)
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }			-- ifSpecific (deprecated)
}
for i=10,20 do
	mibview_ifTable_load[i] = { ["type"] = agentx.VTYPE.Counter32, data = 0 }
end

local ifTable = {1,3,6,1,2,1,2,2}
local ifTable_entry = {unpack(ifTable)}
table.insert(ifTable_entry, 1)		-- ifEntry
table.insert(ifTable_entry, 0)
table.insert(ifTable_entry, ifIndex.data)

for k, v in pairs(mibview_ifTable_load) do
	ifTable_entry[#ifTable_entry - 1] = k
	ax_session.mibview[ifTable_entry] = v
end

ifTable_entry[#ifTable_entry - 1] = 2
local status, result = ax_session:register({subtree=ifTable_entry, range_subid=#ifTable_entry - 1, upper_bound=22})
if not status then
	return false, result.error
end

---- IF-MIB::ifXTable ----

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
--	[14]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifLinkUpDownTrapEnable (FIXME: should be enabled)
	[15]	= { ["type"] = agentx.VTYPE.Gauge32, data = ifXTableMIB.ifHighSpeed },		-- ifHighSpeed
	[16]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifPromiscuousMode
	[17]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifConnectorPresent (FIXME: poll SFP and recover)
	[18]	= { ["type"] = agentx.VTYPE.OctetString, data = "" },				-- ifAlias
	[19]	= { ["type"] = agentx.VTYPE.TimeTicks, data = 0 },				-- ifCounterDiscontinuityTime
}
for i=2,5 do
	mibview_ifXTable_load[i] = { ["type"] = agentx.VTYPE.Counter32, data = 0 }
end
for i=6,13 do
	mibview_ifXTable_load[i] = { ["type"] = agentx.VTYPE.Counter64, data = 0 }
end

local ifXTable = {1,3,6,1,2,1,31,1,1}
local ifXTable_entry = {unpack(ifXTable)}
table.insert(ifXTable_entry, 1)			-- ifXEntry
table.insert(ifXTable_entry, 0)
table.insert(ifXTable_entry, ifIndex.data)	-- ifIndex

for k, v in pairs(mibview_ifXTable_load) do
	ifXTable_entry[#ifXTable_entry - 1] = k
	ax_session.mibview[ifXTable_entry] = v
end

ifXTable_entry[#ifXTable_entry - 1] = 1
local status, result = ax_session:register({subtree=ifXTable_entry, range_subid=#ifXTable_entry - 1, upper_bound=19})
if not status then
	return false, result.error
end

---- IF-MIB::ifStackTable ----

---- ENTITY-MIB::... ----

---- VDSL2-LINE-MIB::xdsl2LineTable ----

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
table.insert(xdsl2LineTable_entry, ifIndex.data)	-- ifIndex

for k, v in pairs(mibview_xdsl2LineTable_load) do
	xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = k
	ax_session.mibview[xdsl2LineTable_entry] = v
end

xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = 1
local status, result = ax_session:register({subtree=xdsl2LineTable_entry, range_subid=#xdsl2LineTable_entry - 1, upper_bound=38})
if not status then
	return false, result.error
end

---- VDSL2-LINE-MIB::xdsl2LineBandTable ----

local xdsl2LineBandTableMIB = {}
xdsl2LineBandTableMIB.xdsl2LineBand = function (request)
	return request.name[#request.name]
end
xdsl2LineBandTableMIB._xdsl2LineBandStatus = function (request, name)
	local xdsl2LineBand = xdsl2LineBandTableMIB.xdsl2LineBand(request)

	local reg
	if xdsl2LineBand == 1 then
		reg = "(US)"
	elseif xdsl2LineBand == 2 then
		reg = "(DS)"
	elseif xdsl2LineBand == 3 then
		reg = "US0"
	elseif xdsl2LineBand == 4 then
		reg = "DS1"
	elseif xdsl2LineBand == 5 then
		reg = "US1"
	elseif xdsl2LineBand == 6 then
		reg = "DS2"
	elseif xdsl2LineBand == 7 then
		reg = "US2"
	elseif xdsl2LineBand == 8 then
		reg = "DS3"
	elseif xdsl2LineBand == 9 then
		reg = "US3"
	elseif xdsl2LineBand == 10 then
		reg = "DS4"
	elseif xdsl2LineBand == 11 then
		reg = "US4"
	end
	reg = name .. " " .. reg

	-- EBM is 24bit so limit is 0x7ffffe and not 0x7ffffffe
	return coroutine.create(function ()
		local result = ebm_session_read({ reg })
		return result[1].int + ((result[1].int < 0x7ffffe) and 0 or (0x7ffffffe - 0x7ffffe))
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
table.insert(xdsl2LineBandTable_entry, ifIndex.data)	-- ifIndex
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
