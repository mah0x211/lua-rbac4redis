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
local sub = string.sub
local find = string.find
local gmatch = string.gmatch

--- decode a encoded role data
--- @param data string
--- @return table<string, boolean>? acl
--- @return any err
local function decode(data)
    local acl = {}
    local len = #data

    local head = 1
    local pos = find(data, '=', head, true)
    while pos do
        local name = sub(data, head, pos - 1)
        if #name == 0 then
            return nil, 'role name must not be empty-string'
        elseif find(name, '[^%w_-]') then
            return nil, 'invalid role name'
        end
        pos = pos + 1

        local tail = find(data, '|', pos, true)
        if not tail then
            tail = len + 1
        end

        local perms = sub(data, pos, tail - 1)
        if find(perms, '[^,%w_-]') then
            return nil, 'invalid role permission'
        end

        local tbl = {}
        for perm in gmatch(perms, '([^,]+)') do
            tbl[perm] = true
        end
        acl[name] = tbl

        head = tail + 1
        pos = find(data, '=', head, true)
    end

    if head <= len then
        return nil, 'invalid role format'
    end

    return acl
end

return decode
