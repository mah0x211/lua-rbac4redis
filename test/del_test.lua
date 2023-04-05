require('luacov')
local testcase = require('testcase')
local set = require('rbac4redis.set')
local del = require('rbac4redis.del')
local redis = require('rbac4redis.redis')
local redis_data = redis.data

function testcase.before_each()
    redis.call('FLUSHALL')
end

function testcase.del()
    -- setup
    for _, v in ipairs({
        {
            keys = {
                'example.com',
                '/foo/bar/baz',
            },
            args = {
                'admin=read',
            },
        },
        {
            keys = {
                'example.com',
                '/foo/:id/baz',
            },
            args = {
                'admin=read',
            },
        },
        {
            keys = {
                'example.com',
                '/foo/:id',
            },
            args = {
                'admin=write',
            },
        },
        {
            keys = {
                'example.com',
                '/foo/:id/baz/:param',
            },
            args = {
                'admin=delete',
            },
        },
        {
            keys = {
                'example.com',
                '/foo/:id/baz/qux/',
            },
            args = {
                'admin=read',
            },
        },
        {
            keys = {
                'example.com',
                '/hello/*world',
            },
            args = {
                'admin=read',
            },
        },
    }) do
        assert.is_true(set(v.keys, v.args))
    end

    -- test that return wrong number of keys error
    assert.match(del({
        'example.com',
    }, {
        'admin=write',
    }), 'wrong number of keys', false)

    -- test that return wrong number of arguments error
    assert.match(del({
        'example.com',
        '/path/name',
    }, {
        'admin=write',
    }), 'wrong number of arguments', false)

    -- test that return 0 if segment does not have acl
    assert.equal(del({
        'example.com',
        '/foo/bar',
    }, {}), 0)

    -- test that return 0 if segment not found
    assert.equal(del({
        'example.com',
        '/foo/bar/',
    }, {}), 0)

    -- test that return 0 if it contains an empty segment
    assert.equal(del({
        'example.com',
        '/foo//baz',
    }, {}), 0)

    -- test that return 0 if it contains a reserved segment
    assert.equal(del({
        'example.com',
        '/foo/$/baz',
    }, {}), 0)

    -- test that return 0 if it contains an empty-named segment
    assert.equal(del({
        'example.com',
        '/foo/:/baz',
    }, {}), 0)

    -- test that return 0 if param segment does not matche
    assert.equal(del({
        'example.com',
        '/foo/:param',
    }, {}), 0)

    -- test that return 0 if glob segment does not matche
    assert.equal(del({
        'example.com',
        '/hello/*param',
    }, {}), 0)

    -- test that return 0 if segment has no acl
    assert.equal(del({
        'example.com',
        '/foo',
    }, {}), 0)

    -- test that del /hello/*world
    assert.equal(del({
        'example.com',
        '/hello/*world',
    }, {}), 1)
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
    })

    -- test that del /foo/:id/baz/:param
    assert.equal(del({
        'example.com',
        '/foo/:id/baz/:param',
    }, {}), 1)
    assert.equal(redis_data(), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
            ['/foo/:id/baz/qux/'] = 'admin=read',
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

    -- test that del /foo/:id/baz/qux/
    assert.equal(del({
        'example.com',
        '/foo/:id/baz/qux/',
    }, {}), 1)
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
            type = 'param',
            route = '/foo/:id',
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

    -- test that del /foo/bar/baz
    assert.equal(del({
        'example.com',
        '/foo/bar/baz',
    }, {}), 1)
    assert.equal(redis_data(), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id'] = 'admin=write',
            ['/foo/:id/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '2',
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
    })

    -- test that del /foo/:id
    assert.equal(del({
        'example.com',
        '/foo/:id',
    }, {}), 1)
    assert.equal(redis_data(), {
        ['RBAC:routes@example.com'] = {
            ['/foo/:id/baz'] = 'admin=read',
        },
        ['RBAC:example.com:/foo'] = {
            ref = '1',
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
    })

    -- test that del /foo/:id/baz
    assert.equal(del({
        'example.com',
        '/foo/:id/baz',
    }, {}), 1)
    assert.equal(redis_data(), {})
end
