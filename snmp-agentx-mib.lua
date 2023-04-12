-- EBM SNMP Subagent - AgentX implementation MIBs
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local agentx, ax_session, ifindex, ebm, ebm_session = ...

local bit32 = require "bit32"

local iftable = {1,3,6,1,2,1,2,2}
local ifxtable = {1,3,6,1,2,1,31,1,1}
local vdsl2MIB = {1,3,6,1,2,1,10,251}

local function ebm_read (regs)
	local status, result = ebm:read(regs)
	if not status then
		error(result)
	end
	return result.data
end

---- ifTable ----

local iftableMIB = {}
iftableMIB.ifDescr = function (request)
	return coroutine.create(function ()
		local result = ebm_read({
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
		local result = ebm_read({ "xdsl2LineStatusAttainableRateDs" })
		return result[1].int * 1000
	end)
end
iftableMIB.ifOperStatus = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "PhyStatus(?)" })
		return ((bit32.band(result[1].int, 0x00ff00) / 256) == 3) and 1 or 2	-- SHOWTIME?
	end)
end
iftableMIB.ifLastChange = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "Link Time" })
		return result[1].int * 100
	end)
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

local ifXtableMIB = {}
ifXtableMIB.ifName = function (request)
	return "ebm" .. ebm_session.addr_print .. "@" .. ebm_session.iface
end
ifXtableMIB.ifHighSpeed = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusAttainableRateDs" })
		return math.floor(result[1].int / 1000)
	end)
end

-- RFC 5650, section 2.1.1
local mibview_ifxtable_load = {
	[1]	= { ["type"] = agentx.VTYPE.OctetString, data = ifXtableMIB.ifName },		-- ifName
	[15]	= { ["type"] = agentx.VTYPE.Gauge32, data = ifXtableMIB.ifHighSpeed },		-- ifHighSpeed
	[14]	= { ["type"] = agentx.VTYPE.Integer, data = 2 },				-- ifLinkUpDownTrapEnable (FIXME: should be enabled)
	[17]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifConnectorPresent (FIXME: poll SFP)
}

local ifxtable_entry = {unpack(ifxtable)}
table.insert(ifxtable_entry, 1)		-- ifXEntry
table.insert(ifxtable_entry, 0)
table.insert(ifxtable_entry, ifindex.data)

for k, v in pairs(mibview_ifxtable_load) do
	ifxtable_entry[#ifxtable_entry - 1] = k
	ax_session.mibview[ifxtable_entry] = v
end

ifxtable_entry[#ifxtable_entry - 1] = 1
local status, result = ax_session:register({subtree=ifxtable_entry, range_subid=#ifxtable_entry - 1, upper_bound=19})
if not status then
	return false, result.error
end

---- ifStackTable - NYI ----

---- ENTITY-MIB - NYI ----

---- xdsl2LineTable ----

local xdsl2LineTableMIB = {}
xdsl2LineTableMIB.xdsl2LineStatusXtuTransSys = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusXtuTransSys" })
		return result[1].raw:sub(3, 3)
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusAttainableRateDs = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusAttainableRateDs" })
		return result[1].int * 1000
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusAttainableRateUs = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusAttainableRateUs" })
		return result[1].int * 1000
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusActProfile = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusActProfile" })
		return result[1].raw:sub(3, 3)
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusElectricalLength = function (request)	-- FIXME convert m to 0.1db
	return coroutine.create(function ()
		local result = ebm_read({ "xdsl2LineStatusElectricalLength" })
		return result[1].int
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusTrellisDs = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "Trellis (DS)" })
		return result[1].int
	end)
end
xdsl2LineTableMIB.xdsl2LineStatusTrellisUs = function (request)
	return coroutine.create(function ()
		local result = ebm_read({ "Trellis (US)" })
		return result[1].int
	end)
end

-- RFC 5650, section 3
local mibview_xdsl2LineTable_load = {
	[13]	= { ["type"] = agentx.VTYPE.Opaque, data = xdsl2LineTableMIB.xdsl2LineStatusXtuTransSys },		-- xdsl2LineStatusXtuTransSys (Issue #1)
	[20]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusAttainableRateDs },	-- xdsl2LineStatusAttainableRateDs
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusAttainableRateUs },	-- xdsl2LineStatusAttainableRateUs
	[26]	= { ["type"] = agentx.VTYPE.Opaque, data = xdsl2LineTableMIB.xdsl2LineStatusActProfile },		-- xdsl2LineStatusActProfile (Issue #1)
	[31]	= { ["type"] = agentx.VTYPE.Gauge32, data = xdsl2LineTableMIB.xdsl2LineStatusElectricalLength },	-- xdsl2LineStatusElectricalLength
	[36]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineTableMIB.xdsl2LineStatusTrellisDs },		-- xdsl2LineStatusTrellisDs
	[37]	= { ["type"] = agentx.VTYPE.Integer, data = xdsl2LineTableMIB.xdsl2LineStatusTrellisUs },		-- xdsl2LineStatusTrellisUs
}

local xdsl2LineTable_entry = {unpack(vdsl2MIB)}
table.insert(xdsl2LineTable_entry, 1)		-- xdsl2Objects
table.insert(xdsl2LineTable_entry, 1)		-- xdsl2Line
table.insert(xdsl2LineTable_entry, 1)		-- xdsl2LineTable
table.insert(xdsl2LineTable_entry, 1)		-- xdsl2LineEntry
table.insert(xdsl2LineTable_entry, 0)
table.insert(xdsl2LineTable_entry, ifindex.data)

for k, v in pairs(mibview_xdsl2LineTable_load) do
	xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = k
	ax_session.mibview[xdsl2LineTable_entry] = v
end

xdsl2LineTable_entry[#xdsl2LineTable_entry - 1] = 1
local status, result = ax_session:register({subtree=xdsl2LineTable_entry, range_subid=#xdsl2LineTable_entry - 1, upper_bound=38})
if not status then
	return false, result.error
end

----

return true
