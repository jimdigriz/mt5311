-- EBM SNMP Subagent - AgentX implementation MIBs
-- Copyright (C) 2023, coreMem Limited <info@coremem.com>
-- SPDX-License-Identifier: AGPL-3.0-only

local agentx, ax_session, ifindex, ebm, ebm_session = ...

local iftable = {1,3,6,1,2,1,2,2}
local vdsl2MIB = {1,3,6,1,2,1,10,251}

local iftable_entry = {unpack(iftable)}
table.insert(iftable_entry, 1)		-- ifEntry
table.insert(iftable_entry, 0)
table.insert(iftable_entry, ifindex.data)

-- RFC 5650, section 2.1.1
local mibview_iftable_load = {
--	[1]	= { ["type"] = agentx.VTYPE.Integer, data = ifindex.data },			-- ifIndex: auto-registered by index_allocate
	[2]	= { ["type"] = agentx.VTYPE.OctetString, data = ebm_session.iface .. ".ebm" },	-- ifDescr
	[3]	= { ["type"] = agentx.VTYPE.Integer, data = vdsl2MIB[#vdsl2MIB] },		-- ifType
	[4]	= { ["type"] = agentx.VTYPE.Integer, data = 1500 },				-- ifMtu
	[5]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifSpeed
	[6]	= { ["type"] = agentx.VTYPE.OctetString, data = ebm_session.addr },		-- ifPhysAddress
	[7]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifAdminStatus
	[8]	= { ["type"] = agentx.VTYPE.Integer, data = 1 },				-- ifOperStatus
	[9]	= { ["type"] = agentx.VTYPE.TimeTicks, data = 69 },				-- ifLastChange
	-- see for loop below
	[21]	= { ["type"] = agentx.VTYPE.Gauge32, data = 0 },				-- ifOutQLen (deprecated)
	[22]	= { ["type"] = agentx.VTYPE.ObjectIdentifer, data = {0,0} }			-- ifSpecific (deprecated)
}
-- ifInOctets, ifInUcastPkts, ifInNUcastPkts (deprecated), ifInDiscards, ifInErrors, ifInUnknownProtos, ifOutOctets, ifOutUcastPkts, ifOutNUcastPkts (deprecated), ifOutDiscards, ifOutErrors
for i=10,20 do
	mibview_iftable_load[i] = { ["type"] = agentx.VTYPE.Counter32, data = 0 }
end
for k, v in pairs(mibview_iftable_load) do
	iftable_entry[#iftable_entry - 1] = k
	ax_session.mibview[iftable_entry] = v
end

iftable_entry[#iftable_entry - 1] = 2
local status, result = ax_session:register({subtree=iftable_entry, range_subid=#iftable_entry - 1, upper_bound=22})
if not status then
	return false, result.error
end

return true
