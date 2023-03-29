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
local find = string.find
local concat = table.concat

--- encode a acl table
--- @param acl table<string, table<string, any>>
--- @return string? data
--- @return any err
local function encode(acl)
    local data = {}

    for name, perms in pairs(acl) do
        if #name == 0 then
            return nil, 'role name must not be empty-string'
        elseif find(name, '[^%w_-]') then
            return nil, 'invalid role name'
        end

        local tbl = {}
        for perm in pairs(perms) do
            if find(perm, '[^%w_-]') then
                return nil, 'invalid role permission'
            end
            tbl[#tbl + 1] = perm
        end
        data[#data + 1] = name .. '=' .. table.concat(tbl, ',')
    end

    return concat(data, '|')
end

return encode
