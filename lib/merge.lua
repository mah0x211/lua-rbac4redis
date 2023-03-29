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
local format = string.format
local decode = require('rbac4redis.decode')
local encode = require('rbac4redis.encode')

-- merge overrides dest_acl with new_acl
--- @param dest_acl string
--- @param new_acl string
--- @return string? data
--- @return any err
local function merge(dest_acl, new_acl)
    local dest, err = decode(dest_acl)
    if not dest then
        return nil, format('failed to decode dest_acl: %s', err)
    end

    local new
    new, err = decode(new_acl)
    if not new then
        return nil, format('failed to decode new_acl: %s', err)
    end

    for name, perms in pairs(new) do
        dest[name] = next(perms) and perms or nil
    end

    local data
    data, err = encode(dest)
    if not data then
        return nil, format('failed to encode acl: %s', err)
    end
    return data
end

return merge
