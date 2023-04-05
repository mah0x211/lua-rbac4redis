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
local tonumber = tonumber
local sub = string.sub
local concat = table.concat
-- luacheck: ignore assert select type concat find gmatch gsub decode encode
local find = string.find

--- @type table<string, fun(string, ...):any>
local redis = require('rbac4redis.redis')
local redcall = redis.call
local rederror = redis.error_reply

--- pathsplit
--- @type fun(s:string, callback:fun(ss:string, s:string, head:integer, tail:integer, ...):(boolean,any), ...:any)
local pathsplit = require('rbac4redis.pathsplit')

--- symbols
local SYM_PARAM = ':'
local SYM_GLOB = '*'
local VSEGMENT = {
    [SYM_PARAM] = SYM_PARAM,
    [SYM_GLOB] = SYM_GLOB,
}

--- traverse
--- @param s string
--- @param _ string
--- @param _ integer
--- @param _ integer
--- @param ctx table<string, string|boolean|table>
--- @return boolean ok
--- @return any err
local function traverse(s, _, _, _, ctx)
    if s == '' then
        -- cannot use empty segment
        return false
    end
    ctx.route[#ctx.route + 1] = s

    local segment = {}
    local sym = sub(s, 1, 1)
    if sym == '/' then
        ctx.key = ctx.key .. s
        ctx.route[#ctx.route] = ''
    elseif not VSEGMENT[sym] then
        if sym == '$' then
            -- cannot use the reserved segment
            return false
        end
        ctx.key = ctx.key .. '/' .. s
    else
        segment.name = sub(s, 2)
        if #segment.name == 0 then
            -- empty-named segment cannot be defined
            return false
        end
        segment.fullname = ctx.key .. '/' .. s

        if sym == SYM_PARAM then
            segment.type = 'param'
        else
            segment.type = 'glob'
            ctx.is_glob = true
        end
        ctx.key = ctx.key .. '/$'
    end
    segment.key = ctx.key
    segment.route = concat(ctx.route, '/')
    ctx.segments[#ctx.segments + 1] = segment

    -- check segment
    local res = redcall('HMGET', ctx.key, 'ref', 'type', 'name')
    local ref, vtype, name = res[1], res[2], res[3]
    if not ref then
        -- not found
        return false
    end
    -- decr reference counter
    segment.ref = tonumber(ref) - 1

    -- segment property does not match
    return segment.type == vtype and segment.name == name
end

--- rbac4redis_del delete the acl data from specified pathname
--- @param keys string[] 1 = domain, 2 = pathname
--- @param args string[] 0
--- @return any
local function rbac4redis_del(keys, args)
    local domain = keys[1]
    local pathname = keys[2]
    if pathname == nil then
        return rederror('wrong number of keys')
    elseif #args > 0 then
        return rederror('wrong number of arguments')
    end

    local routes = 'RBAC:routes@' .. domain
    local res = redcall('HMGET', routes, pathname)
    if not res[1] then
        return 0
    end

    local segments = {}
    local ok, err = pathsplit(pathname, traverse, {
        key = 'RBAC:' .. domain .. ':',
        route = {
            '',
        },
        is_glob = false,
        segments = segments,
    })
    if not ok then
        if err then
            return rederror(err)
        end
        return 0
    end

    -- update segments
    local nseg = #segments
    for i = 1, nseg do
        local seg = segments[i]
        if seg.ref == 0 then
            redcall('DEL', seg.key)
        else
            redcall('HSET', seg.key, 'ref', seg.ref)
        end

        if i == nseg then
            if seg.ref > 0 then
                redcall('HDEL', seg.key, 'route')
            end

            redcall('HDEL', routes, seg.route)
            if redcall('HLEN', routes) == 0 then
                redcall('DEL', routes)
            end
        end
    end

    return 1
end

return rbac4redis_del
