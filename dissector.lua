-- Metanoia - https://metanoia-comm.com/products/xdsl/vdsl2-sfp/
-- Proscend (rebranded) - https://www.proscend.com/en/product/VDSL2-SFP-Modem-Telco/180-T.html
local proto = Proto("EBM", "Ethernet Boot & Management Protocol")

local hdr_flag_mask = {
	["type"] = 0x80
}

local type = {
	["request"] = 0x00,
	["response"] = hdr_flag_mask.type
}

field_type = ProtoField.bool("ebm.type", "Type", 8, { [2] = "Request", [1] = "Response" }, hdr_flag_mask.type)
table.insert(proto.fields, field_type)

field_seq = ProtoField.uint32("ebm.seq", "Sequence Number")
table.insert(proto.fields, field_seq)

field_addr = ProtoField.uint16("ebm.addr", "Address Location")
table.insert(proto.fields, field_addr)

function proto.dissector(tvb, pinfo, tree)
	local len = tvb:len()
	-- 50: request, 46: response
	if not (len == 50 or len == 46) then return end

	pinfo.cols.protocol = proto.name

	local subtree = tree:add(proto, tvb(), "EBM Protocol Data")

	local hdr_tvb = tvb(0, 8)
	local hdr = subtree:add(proto, hdr_tvb(), "Header")
	hdr:add(field_type, hdr_tvb(2, 1))
	hdr:add(field_seq, hdr_tvb(3, 4))

	local payload_tvb = tvb(8)
	local payload = subtree:add(proto, payload_tvb(), "Payload")

	local request = type.request == bit.band(hdr_tvb(2, 1):uint(), hdr_flag_mask.type)
	if request then
		payload:add(field_addr, payload_tvb(2, 2))
	end
end

local dissector = DissectorTable.get("ethertype")
dissector:add(0x6120, proto)
