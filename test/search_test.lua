require('luacov')
local testcase = require('testcase')
local decode = require('cjson').decode
local set = require('rbac4redis.set')
local search = require('rbac4redis.search')
local redis = require('rbac4redis.redis')

function testcase.before_each()
    redis.call('FLUSHALL')
end

function testcase.search()
    -- test that return the ACL of /foo/bar/baz
    assert.is_true(set({
        'example.com',
        '/foo/bar/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(search({
        'example.com',
        '/foo/bar/baz/qux/hello/world',
    }, {})), {
        acl = 'admin=read',
        params = {},
        route = '/foo/bar/baz',
    })

    -- test that return the ACL into /foo/:id/baz
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(search({
        'example.com',
        '/foo/baa/baz',
    }, {})), {
        acl = 'admin=read',
        params = {
            id = 'baa',
        },
        route = '/foo/:id/baz',
    })

    -- test that return the an ACL of /foo/:id/baz
    assert.is_true(set({
        'example.com',
        '/foo/:id',
    }, {
        'admin=write',
    }))
    assert.equal(decode(search({
        'example.com',
        '/foo/qux',
    }, {})), {
        acl = 'admin=write',
        params = {
            id = 'qux',
        },
        route = '/foo/:id',
    })

    -- test that return the ACL of /foo/:id/baz/qux
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/qux',
    }, {
        'admin=post',
    }))
    assert.equal(decode(search({
        'example.com',
        '/foo/baa/baz/qux',
    }, {})), {
        acl = 'admin=post',
        params = {
            id = 'baa',
        },
        route = '/foo/:id/baz/qux',
    })

    -- test that return the ACL of /foo/:id/baz/:param
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/:param',
    }, {
        'admin=delete',
    }))
    assert.equal(decode(search({
        'example.com',
        '/foo/baa/baz/quux',
    }, {})), {
        acl = 'admin=delete',
        params = {
            id = 'baa',
            param = 'quux',
        },
        route = '/foo/:id/baz/:param',
    })

    -- test that return the ACL of /hello/*world
    assert.is_true(set({
        'example.com',
        '/hello/*world',
    }, {
        'admin=put',
    }))
    assert.equal(decode(search({
        'example.com',
        '/hello/foo/bar/baz',
    }, {})), {
        acl = 'admin=put',
        params = {
            world = 'foo/bar/baz',
        },
        route = '/hello/*world',
    })

    -- test that return wrong number of keys error
    assert.match(search({}, {}), 'wrong number of keys', false)
    -- test that return wrong number of arguments error
    assert.match(search({
        'example.com',
        '/foo/bar/baz',
    }, {
        'admin=read',
    }), 'wrong number of arguments', false)
end
