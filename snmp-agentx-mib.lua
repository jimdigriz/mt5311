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
			"CPE Vendor ID (System) [0:2]",
			"CPE Vendor ID (System) [3:5]",
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
ifTableMIB.ifInOctets = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusRtErrorFreeBitsHi", "xdslRtxChStatusRtErrorFreeBitsLo" })
		return bit32.band((result[1].int * (2^24)) + result[2].int, 2^32 - 1)
	end)
end
ifTableMIB.ifInError = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusRtRtxUc" })
		return result[1].int
	end)
end
ifTableMIB.ifOutOctets = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusOtErrorFreeBitsHi", "xdslRtxChStatusOtErrorFreeBitsLo" })
		return bit32.band((result[1].int * (2^24)) + result[2].int, 2^32 - 1)
	end)
end
ifTableMIB.ifOutError = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusOtRtxUc" })
		return result[1].int
	end)
end
local function ifTable_wheel ()
	ebm_session:read({ "PhyStatus(?)", "Link Time" }, coroutine.create(function (result)
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
	[10]	= { ["type"] = agentx.VTYPE.Counter32, data = ifTableMIB.ifInOctets },		-- ifInOctets
	[11]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifInUcastPkts
	[12]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifInNUcastPkts (deprecated)
	[13]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifInDiscards
	[14]	= { ["type"] = agentx.VTYPE.Counter32, data = ifTableMIB.ifInErrors },		-- ifInErrors
	[15]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifInUnknownProtos
	[16]	= { ["type"] = agentx.VTYPE.Counter32, data = ifTableMIB.ifOutOctets },		-- ifOutOctets
	[17]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifOutUcastPkts
	[18]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifOutNUcastPkts (deprecated)
	[19]	= { ["type"] = agentx.VTYPE.Counter32, data = 0 },				-- ifOutDiscards
	[20]	= { ["type"] = agentx.VTYPE.Counter32, data = ifTableMIB.ifOutErrors },		-- ifOutErrors
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifOutQLen (deprecated)
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }			-- ifSpecific (deprecated)
}

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
ifXTableMIB.ifHCInOctets = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusRtErrorFreeBitsHi", "xdslRtxChStatusRtErrorFreeBitsLo" })
		return (result[1].int * (2^24)) + result[2].int
	end)
end
ifXTableMIB.ifHCOutOctets = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdslRtxChStatusOtErrorFreeBitsHi", "xdslRtxChStatusOtErrorFreeBitsLo" })
		return (result[1].int * (2^24)) + result[2].int
	end)
end
ifXTableMIB.ifHighSpeed = function (request)
	return coroutine.create(function ()
		local result = ebm_session_read({ "xdsl2LineStatusAttainableRateDs" })
		return math.floor(result[1].int / 1000)
	end)
end

local mibview_ifXTable_load = {
	[1]	= { ["type"] = agentx.VTYPE.OctetString, data = ifXTableMIB.ifName },		-- ifName
	[6]	= { ["type"] = agentx.VTYPE.Counter64, data = ifXTableMIB.ifHCInOctets },	-- ifHCInOctets
	[7]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCInUcastPkts
	[8]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCInMulticastPkts
	[9]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCInBroadcastPkts
	[10]	= { ["type"] = agentx.VTYPE.Counter64, data = ifXTableMIB.ifHCOutOctets },	-- ifHCOutOctets
	[11]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCOutUcastPkts
	[12]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCOutMulticastPkts
	[13]	= { ["type"] = agentx.VTYPE.Counter64, data = 0 },				-- ifHCOutBroadcastPkts
--	[14]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifLinkUpDownTrapEnable (FIXME: should be enabled)
	[15]	= { ["type"] = agentx.VTYPE.Gauge32, data = ifXTableMIB.ifHighSpeed },		-- ifHighSpeed
	[16]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifPromiscuousMode
	[17]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifConnectorPresent (FIXME: poll SFP and recover)
	[18]	= { ["type"] = agentx.VTYPE.OctetString, data = "" },				-- ifAlias
	[19]	= { ["type"] = agentx.VTYPE.TimeTicks, data = 0 },				-- ifCounterDiscontinuityTime
}

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

---- VDSL2-LINE-MIB::xdsl2LineSegmentTable ----

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

---- VDSL2-LINE-MIB::xdsl2ChannelStatusTable

local xdsl2ChannelStatusTableMIB = {}
xdsl2ChannelStatusTableMIB._direction = function (request)
	return xdsl2LineBandTableMIB.xdsl2LineBand(request)
end
xdsl2ChannelStatusTableMIB.xdsl2ChStatusActDataRate = function (request)
	local reg
	if xdsl2ChannelStatusTableMIB._direction(request.name) == 1 then
		reg = "xdsl2ChStatusActDataRate0 (US)"
	else
		reg = "xdsl2ChStatusActDataRate2 (DS)"
	end
	return coroutine.create(function ()
		local result = ebm_session_read({ reg })
		return result[1].int * 1000
	end)
end
xdsl2ChannelStatusTableMIB.xdsl2ChStatusPrevDataRate = function (request)
	local reg
	if xdsl2ChannelStatusTableMIB._direction(request.name) == 1 then
		reg = "xdsl2ChStatusPrevDataRate0 (US)"
	else
		reg = "xdsl2ChStatusPrevDataRate2 (DS)"
	end
	return coroutine.create(function ()
		local result = ebm_session_read({ reg })
		return result[1].int * 1000
	end)
end

local mibview_xdsl2ChannelStatusTable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2ChannelStatusTableMIB.xdsl2ChStatusUnit },		-- xdsl2ChStatusUnit (not-accessible)
	[2]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2ChannelStatusTableMIB.xdsl2ChStatusActDataRate },	-- xdsl2ChStatusActDataRate
	[3]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2ChannelStatusTableMIB.xdsl2ChStatusPrevDataRate },	-- xdsl2ChStatusPrevDataRate
}

local xdsl2ChannelStatusTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2ChannelStatusTable_entry, 1)			-- xdsl2Objects
table.insert(xdsl2ChannelStatusTable_entry, 2)			-- xdsl2Status
table.insert(xdsl2ChannelStatusTable_entry, 2)			-- xdsl2ChannelStatusTable
table.insert(xdsl2ChannelStatusTable_entry, 1)			-- xdsl2ChannelStatusEntry
table.insert(xdsl2ChannelStatusTable_entry, 0)
table.insert(xdsl2ChannelStatusTable_entry, ifIndex.data)	-- ifIndex
table.insert(xdsl2ChannelStatusTable_entry, 0)			-- xdsl2ChStatusUnit

for k, v in pairs(mibview_xdsl2ChannelStatusTable_load) do
	xdsl2ChannelStatusTable_entry[#xdsl2ChannelStatusTable_entry - 2] = k
	for i=1,2 do
		xdsl2ChannelStatusTable_entry[#xdsl2ChannelStatusTable_entry] = i
		ax_session.mibview[xdsl2ChannelStatusTable_entry] = v
	end

	-- multi-index tables we need to register each entry as registering at the lowest subid does not work
	xdsl2ChannelStatusTable_entry[#xdsl2ChannelStatusTable_entry] = 1
	local status, result = ax_session:register({subtree=xdsl2ChannelStatusTable_entry, range_subid=#xdsl2ChannelStatusTable_entry, upper_bound=2})
	if not status then
		return false, result.error
	end
end

---- VDSL2-LINE-MIB::xdsl2SCStatusTable

---- VDSL2-LINE-MIB::xdsl2SCStatusBandTable

---- VDSL2-LINE-MIB::xdsl2SCStatusSegmentTable

---- VDSL2-LINE-MIB::xdsl2LineInventoryTable

-- Fortunately Cisco provide what we expect to see here in their documentation
--
-- https://www.cisco.com/c/en/us/td/docs/routers/access/1101/software/configuration/guide/b_IR1101config/m_configuring_dsl.html#Cisco_Concept.dita_a2f92f08-5fe7-4cba-87da-5085aad028b4
--
-- > show controllers vdsl 0/0/0
-- Controller VDSL 0/0/0 is UP
-- Daemon Status: UP 
-- XTU-R (DS) XTU-C (US)
--
-- Chip Vendor ID: 'META' 'IKNS'
-- Chip Vendor Specific: 0x0000 0x0101
-- Chip Vendor Country: 0xB500 0xB500
-- Modem Vendor ID: 'META' ' '
-- Modem Vendor Specific: 0x0000 0x2AB0
-- Modem Vendor Country: 0xB500 0x37A0
-- Serial Number Near: E80462D1B001 SFP-V5311-T-R 8431
-- Serial Number Far: ^A5u 
-- Modem Version Near: 1_62_8431 MT5311
-- Modem Version Far: 6.7.0.15IK005010

local xdsl2LineInventoryTableMIB = {}
xdsl2LineInventoryTableMIB.xdsl2LInvUnit = function (request)
	return xdsl2LineBandTableMIB.xdsl2LineBand(request)
end
xdsl2LineInventoryTableMIB._xdsl2LInvVendorId = function (request, name)
	local dir = xdsl2LineInventoryTableMIB.xdsl2LInvUnit(request)
	local regs = {
		"Vendor ID (" .. name .. ") [0:2]",
		"Vendor ID (" .. name .. ") [3:5]",
		"Vendor ID (" .. name .. ") [6:8]"
	}
	for i, v in ipairs(regs) do
		regs[i] = (dir == 1 and "CO" or "CPE") .. " " .. v
	end
	return coroutine.create(function ()
		local result = ebm_session_read(regs)
		local vid = ""
		for i, v in ipairs(result) do
			vid = vid .. v.raw
		end
		return vid:sub(1, 8)
	end)
end
xdsl2LineInventoryTableMIB.xdsl2LInvG994VendorId = function (request)
	return xdsl2LineInventoryTableMIB._xdsl2LInvVendorId(request, "G.994")
end
xdsl2LineInventoryTableMIB.xdsl2LInvSystemVendorId = function (request)
	return xdsl2LineInventoryTableMIB._xdsl2LInvVendorId(request, "System")
end
xdsl2LineInventoryTableMIB.xdsl2LInvVersionNumber = function (request)
	local dir = xdsl2LineInventoryTableMIB.xdsl2LInvUnit(request)
	local regs = {
		"Inventory Version [0:2]",
		"Inventory Version [3:5]",
		"Inventory Version [6:8]",
		"Inventory Version [9:11]",
		"Inventory Version [12:14]",
		"Inventory Version [15:17]"
	}
	for i, v in ipairs(regs) do
		regs[i] = (dir == 1 and "CO" or "CPE") .. " " .. v
	end
	return coroutine.create(function ()
		local result = ebm_session_read(regs)
		local vid = ""
		for i, v in ipairs(result) do
			vid = vid .. v.raw
		end
		return vid:sub(1, 16)
	end)
end
xdsl2LineInventoryTableMIB.xdsl2LInvSerialNumber = function (request)
	local dir = xdsl2LineInventoryTableMIB.xdsl2LInvUnit(request)
	local regs = {
		"Serial Number [0:2]",
		"Serial Number [3:5]",
		"Serial Number [6:8]",
		"Serial Number [9:11]",
		"Serial Number [12:14]",
		"Serial Number [15:17]",
		"Serial Number [18:20]",
		"Serial Number [21:23]",
		"Serial Number [24:26]",
		"Serial Number [27:29]",
		"Serial Number [30:32]"
	}
	for i, v in ipairs(regs) do
		regs[i] = (dir == 1 and "CO" or "CPE") .. " " .. v
	end
	return coroutine.create(function ()
		local result = ebm_session_read(regs)
		local vid = ""
		for i, v in ipairs(result) do
			vid = vid .. v.raw
		end
		return vid
	end)
end

local mibview_xdsl2LineInventoryTable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineInventoryTableMIB.xdsl2LInvUnit },			-- xdsl2LInvUnit (not-accessible)
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = xdsl2LineInventoryTableMIB.xdsl2LInvG994VendorId },	-- xdsl2LInvG994VendorId
	[3]	= { ["type"] = agentx.VTYPE.OctetString, data = xdsl2LineInventoryTableMIB.xdsl2LInvSystemVendorId },	-- xdsl2LInvSystemVendorId
	[4]	= { ["type"] = agentx.VTYPE.OctetString, data = xdsl2LineInventoryTableMIB.xdsl2LInvVersionNumber },	-- xdsl2LInvVersionNumber
	[5]	= { ["type"] = agentx.VTYPE.OctetString, data = xdsl2LineInventoryTableMIB.xdsl2LInvSerialNumber },	-- xdsl2LInvSerialNumber
}

local xdsl2LineInventoryTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2LineInventoryTable_entry, 1)			-- xdsl2Objects
table.insert(xdsl2LineInventoryTable_entry, 3)			-- xdsl2Inventory
table.insert(xdsl2LineInventoryTable_entry, 1)			-- xdsl2LineInventoryTable
table.insert(xdsl2LineInventoryTable_entry, 1)			-- xdsl2LineInventoryEntry
table.insert(xdsl2LineInventoryTable_entry, 0)
table.insert(xdsl2LineInventoryTable_entry, ifIndex.data)	-- ifIndex
table.insert(xdsl2LineInventoryTable_entry, 0)			-- xdsl2LInvUnit

for k, v in pairs(mibview_xdsl2LineInventoryTable_load) do
	xdsl2LineInventoryTable_entry[#xdsl2ChannelStatusTable_entry - 2] = k
	for i=1,2 do
		xdsl2LineInventoryTable_entry[#xdsl2ChannelStatusTable_entry] = i
		ax_session.mibview[xdsl2LineInventoryTable_entry] = v
	end

	-- multi-index tables we need to register each entry as registering at the lowest subid does not work
	xdsl2LineInventoryTable_entry[#xdsl2ChannelStatusTable_entry] = 1
	local status, result = ax_session:register({subtree=xdsl2LineInventoryTable_entry, range_subid=#xdsl2ChannelStatusTable_entry, upper_bound=2})
	if not status then
		return false, result.error
	end
end

---- VDSL2-LINE-MIB::xdsl2PMLineCurrTable

local xdsl2PMLineCurrTableMIB = {}
xdsl2PMLineCurrTableMIB.xdsl2PMLCurrUnit = function (request)
	return xdsl2LineBandTableMIB.xdsl2LineBand(request)
end
xdsl2PMLineCurrTableMIB._xdsl2PMLCurr = function (name)
	return function (request)
		local reg
		if xdsl2PMLineCurrTableMIB.xdsl2PMLCurrUnit(request) == 1 then
			reg = "(US)"
		else
			reg = "(DS)"
		end
		reg = name .. " " .. reg
		return coroutine.create(function ()
			local result = ebm_session_read({ reg })
			return result[1].int
		end)
	end
end

local mibview_xdsl2PMLineCurrTable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2PMLineCurrTableMIB.xdsl2PMLCurrUnit },				-- xdsl2PMLCurrUnit (not-accessible)
--	[2]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2PMLineCurrTableMIB.xdsl2PMLCurr15MValidIntervals },		-- xdsl2PMLCurr15MValidIntervals
--	[3]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2PMLineCurrTableMIB.xdsl2PMLCurr15MInvalidIntervals },		-- xdsl2PMLCurr15MInvalidIntervals
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M Elapsed time") },	-- xdsl2PMLCurr15MTimeElapsed
	[5]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M FECS") },		-- xdsl2PMLCurr15MFecs
	[6]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M ES") },		-- xdsl2PMLCurr15MEs
	[7]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M SES") },		-- xdsl2PMLCurr15MSes
	[8]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M LOSS") },		-- xdsl2PMLCurr15MLoss
	[9]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("15M UAS") },		-- xdsl2PMLCurr15MUas
--	[10]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB.xdsl2PMLCurr1DayValidIntervals },		-- xdsl2PMLCurr1DayValidIntervals
--	[11]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB.xdsl2PMLCurr1DayInvalidIntervals },	-- xdsl2PMLCurr1DayInvalidIntervals
	[12]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day Elapsed time") },	-- xdsl2PMLCurr1DayTimeElapsed
	[13]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day FECS") },		-- xdsl2PMLCurr1DayFecs
	[14]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day ES") },		-- xdsl2PMLCurr1DayEs
	[15]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day SES") },		-- xdsl2PMLCurr1DaySes
	[16]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day LOSS") },		-- xdsl2PMLCurr1DayLoss
	[17]	= { ["type"] = agentx.VTYPE.Counter32, data = xdsl2PMLineCurrTableMIB._xdsl2PMLCurr("1Day UAS") },		-- xdsl2PMLCurr1DayUas
}

local xdsl2PMLineCurrTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2PMLineCurrTable_entry, 1)			-- xdsl2Objects
table.insert(xdsl2PMLineCurrTable_entry, 4)			-- xdsl2PM
table.insert(xdsl2PMLineCurrTable_entry, 1)			-- xdsl2PMLine
table.insert(xdsl2PMLineCurrTable_entry, 1)			-- xdsl2PMLineCurrTable
table.insert(xdsl2PMLineCurrTable_entry, 1)			-- xdsl2PMLineCurrEntry
table.insert(xdsl2PMLineCurrTable_entry, 0)
table.insert(xdsl2PMLineCurrTable_entry, ifIndex.data)		-- ifIndex
table.insert(xdsl2PMLineCurrTable_entry, 0)			-- xdsl2PMLCurrUnit

for k, v in pairs(mibview_xdsl2PMLineCurrTable_load) do
	xdsl2PMLineCurrTable_entry[#xdsl2PMLineCurrTable_entry - 2] = k
	for i=1,2 do
		xdsl2PMLineCurrTable_entry[#xdsl2PMLineCurrTable_entry] = i
		ax_session.mibview[xdsl2PMLineCurrTable_entry] = v
	end

	-- multi-index tables we need to register each entry as registering at the lowest subid does not work
	xdsl2PMLineCurrTable_entry[#xdsl2PMLineCurrTable_entry] = 1
	local status, result = ax_session:register({subtree=xdsl2PMLineCurrTable_entry, range_subid=#xdsl2PMLineCurrTable_entry, upper_bound=2})
	if not status then
		return false, result.error
	end
end

---- VDSL2-LINE-MIB::xdsl2PMLineInitCurrTable

---- VDSL2-LINE-MIB::xdsl2PMChCurrTable

---- VDSL2-LINE-MIB::xdsl2PMLineHist15MinTable

---- VDSL2-LINE-MIB::xdsl2PMLineInitHist15MinTable

---- VDSL2-LINE-MIB::xdsl2PMChHist15MinTable

---- VDSL2-LINE-MIB::xdsl2PMLineHist1DayTable

---- VDSL2-LINE-MIB::xdsl2PMLineInitHist1DayTable

---- VDSL2-LINE-MIB::xdsl2PMChHist1DTable

----

return true
