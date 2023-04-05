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
-- module
-- luacheck: ignore cjson
local cjson = cjson or require('cjson')
local sub = string.sub
-- luacheck: ignore assert select type concat find gmatch gsub decode encode
local find = string.find

--- @type table<string, fun(string, ...):any>
local redis = require('rbac4redis.redis')
local redcall = redis.call
local rederror = redis.error_reply

--- pathsplit
--- @type fun(s:string, callback:fun(idx:integer, ss:string, ...):(boolean,any), ...:any)
local pathsplit = require('rbac4redis.pathsplit')

--- traverse
---@param s string
---@param pathname string
---@param head integer
---@param _ integer
---@param ctx table<string, string|boolean|table>
---@return boolean ok
---@return any err
local function traverse(s, pathname, head, _, ctx)
    if s == '' then
        -- cannot use empty segment
        return false
    end

    local key = ctx.key .. (s == '/' and s or '/' .. s)
    local res = redcall('HMGET', key, 'ref', 'route', 'type', 'name')
    local ref, route, vtype, name = res[1], res[2], res[3], res[4]
    if not ref then
        if s == '/' then
            -- not found
            return false
        end

        key = ctx.key .. '/$'
        res = redcall('HMGET', key, 'ref', 'route', 'type', 'name')
        ref, route, vtype, name = res[1], res[2], res[3], res[4]
        if not ref then
            -- not found
            return false
        end
    end
    ctx.key = key
    ctx.route = route
    if vtype == 'param' then
        ctx.params[name] = s
    elseif vtype == 'glob' then
        ctx.params[name] = sub(pathname, head)
        -- done
        return false
    end

    return true
end

--- rbac4redis_search
--- @param keys string[] 1 = domain, 2 = pathname
--- @param args string[] 0
--- @return any
local function rbac4redis_search(keys, args)
    local domain = keys[1]
    local pathname = keys[2]
    if #keys ~= 2 then
        return rederror('wrong number of keys')
    elseif #args ~= 0 then
        return rederror('wrong number of arguments')
    end

    local ctx = {
        key = 'RBAC:' .. domain .. ':',
        params = {},
        is_glob = false,
    }
    local ok, err = pathsplit(pathname, traverse, ctx)
    if not ok then
        if err then
            return rederror(err)
        elseif not ctx.route then
            -- not found
            return '{}'
        end
    end

    ctx.key, ctx.is_glob = nil, nil
    local res = redcall('HMGET', 'RBAC:routes@' .. domain, ctx.route)
    ctx.acl = res[1]
    return cjson.encode(ctx)
end

return rbac4redis_search
