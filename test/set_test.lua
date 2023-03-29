require('luacov')
local testcase = require('testcase')
local set = require('rbac4redis.set')
local redis = require('rbac4redis.redis')
local redis_data = redis.data

function testcase.before_each()
    redis.call('FLUSHALL')
end

function testcase.set()
    -- test that set an ACL into /foo/bar/baz
    assert.is_true(set({
        'example.com',
        '/foo/bar/baz',
    }, {
        'admin=read',
    }))
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.equal(redis_data(), {
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
    assert.match(set({
        'example.com',
    }, {
        'admin=write',
    }), 'wrong number of keys', false)

    -- test that return wrong number of arguments error
    assert.match(set({
        'example.com',
        '/foo/bar',
    }, {}), 'wrong number of arguments', false)

    -- test that return cannot use the reserved segment error
    assert.match(set({
        'example.com',
        '/foo/$/bar',
    }, {
        'admin=write',
    }), 'cannot use the reserved segment', false)

    -- test that return cannot use empty segment error
    assert.match(set({
        'example.com',
        '/foo//bar',
    }, {
        'admin=write',
    }), 'cannot use empty segment', false)

    -- test that return segment cannot be defined after a glob segment error
    assert.match(set({
        'example.com',
        '/qux/*param/bar',
    }, {
        'admin=write',
    }), 'segment cannot be defined after a glob segment', false)

    -- test that return empty-named segment cannot be defined error
    assert.match(set({
        'example.com',
        '/foo/:id/:',
    }, {
        'admin=write',
    }), 'empty-named segment cannot be defined')

    -- test that return glob segments cannot be insert error
    assert.match(set({
        'example.com',
        '/*foo',
    }, {
        'admin=write',
    }), 'glob segments cannot be inserted into an existing path', false)

    -- test that return already defined error
    assert.match(set({
        'example.com',
        '/foo/:id2',
    }, {
        'admin=write',
    }), ':id" is already defined', false)

    -- test that return cannot be defined after glob segment error
    assert.match(set({
        'example.com',
        '/hello/world/segment',
    }, {
        'admin=write',
    }), 'cannot be defined after glob segment', false)

    -- test that return failed to merge acl settings error
    assert.match(set({
        'example.com',
        '/',
    }, {
        '=write',
    }), 'failed to decode new_acl', false)
end
