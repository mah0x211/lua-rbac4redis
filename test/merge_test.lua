require('luacov')
local testcase = require('testcase')
local decode = require('rbac4redis.decode')
local merge = require('rbac4redis.merge')

function testcase.merge()
    -- test that overrides a user role
    local res, err = merge('admin=read,write,delete|user=read', 'user=write')
    assert.is_nil(err)
    assert.equal(decode(res), {
        admin = {
            read = true,
            write = true,
            delete = true,
        },
        user = {
            write = true,
        },
    })

    -- test that delete a admin role
    res, err = merge('admin=read,write,delete|user=read,write', 'admin=')
    assert.is_nil(err)
    assert.equal(decode(res), {
        user = {
            read = true,
            write = true,
        },
    })

    -- test that delete admin and user roles
    res, err = merge('admin=read,write,delete|user=read,write', 'admin=|user=')
    assert.is_nil(err)
    assert.equal(decode(res), {})

    -- test that failed to decode dest_acl error
    res, err = merge('admin=read,write,delete|=read', 'user=read')
    assert.is_nil(res)
    assert.match(err, 'failed to decode dest_acl', false)

    -- test that failed to decode new_roles error
    res, err = merge('admin=read,write,delete|user=read', '=write')
    assert.is_nil(res)
    assert.match(err, 'failed to decode new_acl', false)
end

