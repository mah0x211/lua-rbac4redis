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
local format = string.format
local sub = string.sub
local concat = table.concat
-- luacheck: ignore assert select type find gmatch gsub decode encode
local find = string.find
local gmatch = string.gmatch

--- @type table<string, fun(string, ...):any>
local redis = require('rbac4redis.redis')
local redcall = redis.call
local rederror = redis.error_reply

--- pathsplit
--- @type fun(s:string, callback:fun(ss:string, s:string, head:integer, tail:integer, ...):(boolean,any), ...:any)
local pathsplit = require('rbac4redis.pathsplit')

--- decode
--- @type fun(s:string):table<string, boolean>?,any
local decode = require('rbac4redis.decode')

--- encode
--- @type fun(acl:table<string, boolean>):any
local encode = require('rbac4redis.encode')

--- merge
--- @type fun(dest_acl:string, new_acl:string):string?,any
local merge = require('rbac4redis.merge')

--- symbols
local SYM_PARAM = ':'
local SYM_GLOB = '*'
local VSEGMENT = {
    [SYM_PARAM] = SYM_PARAM,
    [SYM_GLOB] = SYM_GLOB,
}

--- traverse
--- @param s string
--- @param pathname string
--- @param _ integer
--- @param _ integer
--- @param ctx table<string, string|boolean|table>
--- @return boolean ok
--- @return any err
local function traverse(s, pathname, _, _, ctx)
    if s == '' then
        return false, 'cannot use empty segment'
    elseif ctx.is_glob then
        return false, 'segment cannot be defined after a glob segment'
    end
    ctx.route[#ctx.route + 1] = s

    local segment = {
        ref = 1,
    }
    local key = ctx.key
    local sym = sub(s, 1, 1)
    if sym == '/' then
        ctx.key = key .. s
        ctx.route[#ctx.route] = ''
    elseif not VSEGMENT[sym] then
        if sym == '$' then
            return false, format('cannot use the reserved segment %q', sym)
        end
        ctx.key = key .. '/' .. s
    else
        segment.name = sub(s, 2)
        if #segment.name == 0 then
            return false, 'empty-named segment cannot be defined'
        end

        if sym == SYM_PARAM then
            segment.type = 'param'
        elseif #(redcall('KEYS', key .. '/*')) > 0 then
            return false,
                   'glob segments cannot be inserted into an existing path'
        else
            ctx.is_glob = true
            segment.type = 'glob'
        end

        ctx.key = key .. '/$'
    end
    segment.key = ctx.key
    segment.route = concat(ctx.route, '/')
    ctx.segments[#ctx.segments + 1] = segment

    -- check variable segment
    local res = redcall('HMGET', key .. '/$', 'ref', 'type', 'name')
    local ref, vtype, name = res[1], res[2], res[3]
    if ref then
        if vtype then
            if segment.type then
                if vtype and segment.type ~= vtype or segment.name ~= name then
                    return false,
                           format(
                               'named segment %q cannot be defined: %q is already defined',
                               segment.route, ':' .. name)
                end
                segment.ref = tonumber(ref or 0) + 1
            elseif vtype == 'glob' then
                return false,
                       format(
                           'segment %q cannot be defined after glob segment %q',
                           pathname, '*' .. name)
            end
        end
    end

    return true
end

--- rbac4redis_set sets the acl data into specified pathname
--- @param keys string[] 1 = domain, 2 = pathname
--- @param args string[] 1 = encoded_acl
--- @return any
local function rbac4redis_set(keys, args)
    local domain = keys[1]
    local pathname = keys[2]
    if pathname == nil then
        return rederror('wrong number of keys')
    elseif #args ~= 1 then
        return rederror('wrong number of arguments')
    end

    local new_acl, err = merge('', args[1])
    if not new_acl then
        return rederror(err)
    end

    local routes = 'RBAC:routes@' .. domain
    local res = redcall('HMGET', routes, pathname)
    local old_acl = res[1]
    if old_acl then
        -- merge old and new acl settings
        new_acl, err = merge(old_acl, new_acl)
        if not new_acl then
            return rederror(format('failed to merge acl settings: %s', err))
        end
        -- update acl
        redcall('HSET', routes, pathname, new_acl)
        return true
    end

    local segments = {}
    local ok
    ok, err = pathsplit(pathname, traverse, {
        key = 'RBAC:' .. domain .. ':',
        route = {
            '',
        },
        is_glob = false,
        segments = segments,
    })
    if not ok then
        return rederror(err)
    end

    -- add new route
    local nseg = #segments
    for i = 1, nseg do
        local seg = segments[i]
        if i == nseg then
            -- set last segment fields
            redcall('HSET', seg.key, 'ref', seg.ref, 'route', seg.route)
            if seg.type then
                redcall('HSET', seg.key, 'name', seg.name, 'type', seg.type)
            end
            redcall('HSET', routes, seg.route, new_acl)
        elseif seg.type then
            redcall('HSET', seg.key, 'ref', seg.ref, 'name', seg.name, 'type',
                    seg.type)
        else
            redcall('HINCRBY', seg.key, 'ref', 1)
        end
    end

    return true
end

return rbac4redis_set
