require('luacov')
local testcase = require('testcase')
local decode = require('rbac4redis.decode')

function testcase.decode()
    -- test that decode acl
    local res, err = decode('admin=read,write,delete|user=read')
    assert.is_nil(err)
    assert.equal(res, {
        admin = {
            read = true,
            write = true,
            delete = true,
        },
        user = {
            read = true,
        },
    })

    -- test that decode role with no permissions
    res, err = decode('admin=|user=read')
    assert.is_nil(err)
    assert.equal(res, {
        admin = {},
        user = {
            read = true,
        },
    })

    -- test that decode empty acl
    res, err = decode('')
    assert.is_nil(err)
    assert.equal(res, {})

    -- test that multiple roles with various permissions
    res, err = decode('admin=read,write,delete|user=read|guest=')
    assert.is_nil(err)
    assert.equal(res, {
        admin = {
            read = true,
            write = true,
            delete = true,
        },
        user = {
            read = true,
        },
        guest = {},
    })

    -- test that return empty role name error
    res, err = decode('admin=read,write,delete|=read')
    assert.is_nil(res)
    assert.equal(err, 'role name must not be empty-string')

    -- test that return invalid role name error
    res, err = decode('admin$=read,write,delete|user=read')
    assert.is_nil(res)
    assert.equal(err, 'invalid role name')

    -- test that return invalid role permission error
    res, err = decode('admin=read,write,delete|user=read,write@')
    assert.is_nil(res)
    assert.equal(err, 'invalid role permission')

    -- test that return invalid role formatted error
    res, err = decode('admin')
    assert.is_nil(res)
    assert.equal(err, 'invalid role format')
end

