require('luacov')
local testcase = require('testcase')
local encode = require('rbac4redis.encode')
local decode = require('rbac4redis.decode')

function testcase.encode()
    -- test that encode acl to string
    local acl = {
        admin = {
            read = true,
            write = true,
            delete = true,
        },
        user = {
            read = true,
            write = true,
        },
    }
    local res, err = encode(acl)
    assert.is_nil(err)
    assert.equal(decode(res), acl)

    -- test that return an empty role name error
    acl = {
        [''] = {
            read = true,
        },
    }
    res, err = encode(acl)
    assert.is_nil(res)
    assert.equal(err, 'role name must not be empty-string')

    -- test that return an invalid role name error
    acl = {
        ['&*!'] = {
            read = true,
        },
    }
    res, err = encode(acl)
    assert.is_nil(res)
    assert.equal(err, 'invalid role name')

    -- test that return an invalid role permission error
    acl = {
        admin = {
            ['&*!'] = true,
        },
    }
    res, err = encode(acl)
    assert.is_nil(res)
    assert.equal(err, 'invalid role permission')
end

