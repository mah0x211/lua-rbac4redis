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

--- split
--- @param pathname string
--- @param callback fun(ss:string, s:string, head:integer, tail:integer, ...:any):(boolean,any)
--- @param ... any
--- @return boolean ok
--- @return any err
--- @return integer? pos
local function pathsplit(pathname, callback, ...)
    if sub(pathname, 1, 1) ~= '/' then
        return false, 'pathname must be absolute path'
    end

    local sep = '/'
    local idx = 1
    local pos = 2
    local head, tail = find(pathname, sep, pos, true)
    while head do
        local ok, err = callback(sub(pathname, pos, head - 1), pathname, pos,
                                 pos == head and head or head - 1, ...)
        if not ok then
            return false, err
        end
        idx = idx + 1
        pos = tail + 1
        head, tail = find(pathname, sep, pos, true)
    end

    if pos <= #pathname then
        -- push remaining string
        return callback(sub(pathname, pos), pathname, pos, #pathname, ...)
    end
    -- push empty-string
    return callback('/', pathname, #pathname, #pathname, ...)
end

return pathsplit
