require('luacov')
local testcase = require('testcase')
local decode = require('cjson').decode
local set = require('rbac4redis.set')
local list = require('rbac4redis.list')
local redis = require('rbac4redis.redis')

function testcase.before_each()
    redis.call('FLUSHALL')
end

function testcase.list()
    -- test that set an ACL into /foo/bar/baz
    assert.is_true(set({
        'example.com',
        '/foo/bar/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/bar/baz'] = 'admin=read',
    })

    -- test that set an ACL into /foo/:id/baz
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id/baz'] = 'admin=read',
        ['/foo/bar/baz'] = 'admin=read',
    })

    -- test that set an ACL into /foo/:id
    assert.is_true(set({
        'example.com',
        '/foo/:id',
    }, {
        'admin=write',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id'] = 'admin=write',
        ['/foo/:id/baz'] = 'admin=read',
        ['/foo/bar/baz'] = 'admin=read',
    })

    -- test that set an ACL into /foo/:id/baz/:param
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/:param',
    }, {
        'admin=delete',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id'] = 'admin=write',
        ['/foo/:id/baz'] = 'admin=read',
        ['/foo/:id/baz/:param'] = 'admin=delete',
        ['/foo/bar/baz'] = 'admin=read',
    })

    -- test that set an ACL into /foo/:id/baz/qux/
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/qux/',
    }, {
        'admin=read',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id'] = 'admin=write',
        ['/foo/:id/baz'] = 'admin=read',
        ['/foo/:id/baz/:param'] = 'admin=delete',
        ['/foo/:id/baz/qux/'] = 'admin=read',
        ['/foo/bar/baz'] = 'admin=read',
    })

    -- test that set an ACL into /hello/*world
    assert.is_true(set({
        'example.com',
        '/hello/*world',
    }, {
        'admin=read',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id'] = 'admin=write',
        ['/foo/:id/baz'] = 'admin=read',
        ['/foo/:id/baz/:param'] = 'admin=delete',
        ['/foo/:id/baz/qux/'] = 'admin=read',
        ['/foo/bar/baz'] = 'admin=read',
        ['/hello/*world'] = 'admin=read',
    })

    -- test that update existing ACL
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz',
    }, {
        'admin=write',
    }))
    assert.equal(decode(list({
        'example.com',
    }, {})), {
        ['/foo/:id'] = 'admin=write',
        ['/foo/:id/baz'] = 'admin=write',
        ['/foo/:id/baz/:param'] = 'admin=delete',
        ['/foo/:id/baz/qux/'] = 'admin=read',
        ['/foo/bar/baz'] = 'admin=read',
        ['/hello/*world'] = 'admin=read',
    })

    -- test that return wrong number of keys error
    assert.match(list({}, {}), 'wrong number of keys', false)
    assert.match(list({
        'example.com',
        '/foo/bar',
    }, {}), 'wrong number of keys', false)

    -- test that return wrong number of arguments error
    assert.match(list({
        'example.com',
    }, {
        'admin=read',
    }), 'wrong number of arguments', false)
end
