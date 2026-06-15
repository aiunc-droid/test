assert(getscriptbytecode, "exploit does not support getscriptbytecode.")

local last = 0
local httpservice = cloneref and cloneref(game:GetService("HttpService")) or game:GetService("HttpService")

getgenv().decompile = function(scr)
    local ok, bytecode = pcall(getscriptbytecode, scr)
    if not ok then
        return "-- failed to read script bytecode\n--[[\n" .. tostring(bytecode) .. "\n--]]"
    end

    -- FIX: If bytecode is a Luau buffer, convert it to a standard string
    if typeof(bytecode) == "buffer" then
        bytecode = buffer.tostring(bytecode)
    else
        -- Fallback to force it into a string format just in case
        bytecode = tostring(bytecode)
    end

    local elapsed = os.clock() - last
    if elapsed < 0.12 then
        task.wait(0.12 - elapsed)
    end

    -- Use built-in crypt base64 if available (much faster), otherwise use fallback
    local encoder = (crypt and crypt.base64encode) or base64_encode
    if not encoder then
        encoder = function(data)
            local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            return ((data:gsub('.', function(x)
                local r,byte = '',x:byte()
                for i=8,1,-1 do
                    r = r .. (byte % 2^i - byte % 2^(i-1) > 0 and '1' or '0')
                end
                return r
            end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
                if #x < 6 then return '' end
                local c = 0
                for i=1,6 do
                    c = c + (x:sub(i,i) == '1' and 2^(6-i) or 0)
                end
                return b:sub(c+1,c+1)
            end)..({ '', '==', '=' })[#data % 3 + 1])
        end
    end

    local res = request({
        Url = "https://api.lua.expert/decompile",
        Method = "POST",
        Headers = {
            ["content-type"] = "application/json"
        },
        Body = httpservice:JSONEncode({
            script = encoder(bytecode)
        })
    })

    last = os.clock()

    if not res or res.StatusCode ~= 200 then
        return "-- api request error\n--[[\n" .. (res and res.Body or "no response") .. "\n--]]"
    end

    -- The API usually returns a JSON object. If it returns raw text, 
    -- you can leave this as res.Body. If it errors, you might need to decode it.
    local success, decoded = pcall(function() return httpservice:JSONDecode(res.Body) end)
    if success symptoms and type(decoded) == "table" and decoded.decompiled then
        return decoded.decompiled
    end

    return res.Body
end
