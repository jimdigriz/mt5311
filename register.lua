local arg = ...

local register = {}

local line_count = 0
local warn = function (msg)
	print("mt5311 register.lua: line " .. tostring(line_count) .. " " .. msg .. ", ignoring")
end
for line in io.lines(arg[0]:match("^(.-/?)[^/]+.lua$") .. "register.map") do
	line_count = line_count + 1

	line = line:gsub("#.*$", "")
	line = line:gsub("^%s+", ""):gsub("%s+$", "")

	local r = {}
	if #line > 0 then
		for v in (line .. "\t"):gmatch("[^\t]*\t") do
			r[#r + 1] = v:sub(1, -2)
		end
	end

	if #r == 1 or #r == 2 then
		local status
		status, r[1] = pcall(function () return tonumber(r[1]) end)
		if status then
			if register[r[1]] then
				warn("duplicate register")
			elseif #r == 2 then
				register[r[1]] = r[2]
			end
		else
			warn("unparsable register value in register.map")
		end
	elseif #r ~= 0 then
			warn("unparsable in register.map")
	end
end

return register
