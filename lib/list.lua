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
-- luacheck: ignore cjson
local cjson = cjson or require('cjson')

--- @type table<string, fun(string, ...):any>
local redis = require('rbac4redis.redis')
local redcall = redis.call
local rederror = redis.error_reply

--- rbac4redis_list get the routes
--- @param keys string[] 1 = domain
--- @param args string[]
--- @return any
local function rbac4redis_list(keys, args)
    local domain = keys[1]
    if #keys ~= 1 then
        return rederror('wrong number of keys')
    elseif #args > 0 then
        return rederror('wrong number of arguments')
    end

    local routes = {}
    local arr = redcall('HGETALL', 'RBAC:routes@' .. domain)
    for i = 1, #arr, 2 do
        routes[arr[i]] = arr[i + 1]
    end
    return cjson.encode(routes)
end

return rbac4redis_list
