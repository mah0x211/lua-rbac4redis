require('luacov')
local testcase = require('testcase')
local decode = require('cjson').decode
local set = require('rbac4redis.set')
local dump = require('rbac4redis.dump')
local redis = require('rbac4redis.redis')

function testcase.before_each()
    redis.call('FLUSHALL')
end

function testcase.dump()
    -- test that set an ACL into /foo/bar/baz
    assert.is_true(set({
        'example.com',
        '/foo/bar/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/bar/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
    })

    -- test that set an ACL into /foo/:id/baz
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz',
    }, {
        'admin=read',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/bar/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '2',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '1',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '1',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
    })

    -- test that set an ACL into /foo/:id
    assert.is_true(set({
        'example.com',
        '/foo/:id',
    }, {
        'admin=write',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/bar/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '3',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '2',
            route = '/foo/:id',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '1',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
    })

    -- test that set an ACL into /foo/:id/baz/:param
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/:param',
    }, {
        'admin=delete',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/:id/baz/:param'] = 'admin=delete',
            ['/foo/bar/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '4',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '3',
            route = '/foo/:id',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '2',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/$/baz/$'] = {
            name = 'param',
            ref = '1',
            route = '/foo/:id/baz/:param',
            type = 'param',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
    })

    -- test that set an ACL into /foo/:id/baz/qux/
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz/qux/',
    }, {
        'admin=read',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/:id/baz/:param'] = 'admin=delete',
            ['/foo/:id/baz/qux/'] = 'admin=read',
            ['/foo/bar/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '5',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '4',
            route = '/foo/:id',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '3',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/$/baz/$'] = {
            name = 'param',
            ref = '1',
            type = 'param',
            route = '/foo/:id/baz/:param',
        },
        ['RBAC:example.com:/foo/$/baz/qux'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/$/baz/qux/'] = {
            ref = '1',
            route = '/foo/:id/baz/qux/',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
    })

    -- test that set an ACL into /hello/*world
    assert.is_true(set({
        'example.com',
        '/hello/*world',
    }, {
        'admin=read',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/:id/baz/:param'] = 'admin=delete',
            ['/foo/:id/baz/qux/'] = 'admin=read',
            ['/foo/bar/baz'] = 'admin=read',
            ['/hello/*world'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '5',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '4',
            route = '/foo/:id',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '3',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/$/baz/$'] = {
            name = 'param',
            ref = '1',
            route = '/foo/:id/baz/:param',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz/qux'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/$/baz/qux/'] = {
            ref = '1',
            route = '/foo/:id/baz/qux/',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
        ['RBAC:example.com:/hello'] = {
            ref = '1',
        },
        ['RBAC:example.com:/hello/$'] = {
            name = 'world',
            ref = '1',
            route = '/hello/*world',
            type = 'glob',
        },
    })

    -- test that update existing ACL
    assert.is_true(set({
        'example.com',
        '/foo/:id/baz',
    }, {
        'admin=write',
    }))
    assert.equal(decode(dump({
        'example.com',
    }, {})), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=write',
            ['/foo/:id/baz/:param'] = 'admin=delete',
            ['/foo/:id/baz/qux/'] = 'admin=read',
            ['/foo/bar/baz'] = 'admin=read',
            ['/hello/*world'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '5',
        },
        ['RBAC:example.com:/foo/$'] = {
            name = 'id',
            ref = '4',
            route = '/foo/:id',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz'] = {
            ref = '3',
            route = '/foo/:id/baz',
        },
        ['RBAC:example.com:/foo/$/baz/$'] = {
            name = 'param',
            ref = '1',
            route = '/foo/:id/baz/:param',
            type = 'param',
        },
        ['RBAC:example.com:/foo/$/baz/qux'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/$/baz/qux/'] = {
            ref = '1',
            route = '/foo/:id/baz/qux/',
        },
        ['RBAC:example.com:/foo/bar'] = {
            ref = '1',
        },
        ['RBAC:example.com:/foo/bar/baz'] = {
            ref = '1',
            route = '/foo/bar/baz',
        },
        ['RBAC:example.com:/hello'] = {
            ref = '1',
        },
        ['RBAC:example.com:/hello/$'] = {
            name = 'world',
            ref = '1',
            route = '/hello/*world',
            type = 'glob',
        },
    })

    -- test that return wrong number of keys error
    assert.match(dump({}, {}), 'wrong number of keys', false)
    assert.match(dump({
        'example.com',
        '/foo/bar',
    }, {}), 'wrong number of keys', false)

    -- test that return wrong number of arguments error
    assert.match(dump({
        'example.com',
    }, {
        'admin=read',
    }), 'wrong number of arguments', false)
end
