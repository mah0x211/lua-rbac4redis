--
-- Copyright (C) 2023 Masatoshi Fukunaga
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
local DATA = {}

local function KEYS(key)
    -- NOTE: a key must be end with a '*' character
    local pattern = string.gsub(string.sub(key, 1, #key - 1), '%$', '[^/]+')
    local keys = {}

    for k in pairs(DATA) do
        if string.find(k, pattern) then
            keys[#keys + 1] = k
        end
    end

    return keys
end

local function HSET(key, ...)
    local obj = DATA[key]
    if not obj then
        obj = {}
        DATA[key] = obj
    end

    local retval = 0
    local fields = {
        ...,
    }
    for i = 1, select('#', ...), 2 do
        local k = fields[i]
        local v = fields[i + 1]
        assert(type(k) == 'string')
        assert(type(v) ~= 'nil')
        obj[k] = tostring(v)
        retval = retval + (v and 1 or 0)
    end

    return retval
end

local function HDEL(key, ...)
    local obj = DATA[key]
    if not obj then
        return 0
    end

    local n = 0
    local fields = {
        ...,
    }
    for i = 1, select('#', ...), 2 do
        assert(type(fields[i]) == 'string')
        local field = fields[i]
        if obj[field] then
            obj[field] = nil
            n = n + 1
        end
    end
    return n
end

local function HGETALL(key)
    local obj = DATA[key]
    if not obj then
        return nil
    end

    local values = {}
    for k, v in pairs(obj) do
        values[#values + 1] = k
        values[#values + 1] = v
    end
    return values
end

local function HMGET(key, ...)
    local obj = DATA[key]
    if not obj then
        return {}
    end

    local values = {}
    local nfield = select('#', ...)
    local fields = {
        ...,
    }
    for i = 1, nfield do
        assert(type(fields[i]) == 'string')
        values[i] = obj[fields[i]]
    end

    return values
end

local function HINCRBY(key, field, incr)
    local obj = DATA[key]
    if not obj then
        obj = {
            [field] = incr,
        }
        DATA[key] = obj
        return incr
    elseif obj[field] == nil then
        obj[field] = incr
        return incr
    elseif type(obj[field]) == 'number' then
        obj[field] = obj[field] + incr
        return obj[field]
    end

    return 'hash value is not an integer'
end

local function FLUSHALL()
    DATA = {}
    return true
end

local commands = {
    KEYS = KEYS,
    HSET = HSET,
    HGETALL = HGETALL,
    HMGET = HMGET,
    HINCRBY = HINCRBY,
    FLUSHALL = FLUSHALL,
}

local function call(cmd, ...)
    return commands[cmd](...)
end

local function error_reply(s)
    return s
end

local function data()
    return DATA
end

return {
    data = data,
    call = call,
    error_reply = error_reply,
}
