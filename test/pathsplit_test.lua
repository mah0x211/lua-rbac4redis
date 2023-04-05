require('luacov')
local testcase = require('testcase')
local pathsplit = require('rbac4redis.pathsplit')

function testcase.pathsplit()
    -- test that split a string with /
    local output = {}
    assert(pathsplit('/one/two/three/four', function(ss, s, head, tail)
        assert.equal(s, '/one/two/three/four')
        assert.is_int(head)
        assert.is_int(tail)
        assert.less_or_equal(head, tail)
        output[#output + 1] = ss
        return true
    end))
    assert.equal(output, {
        'one',
        'two',
        'three',
        'four',
    })

    -- test that split a single segment
    output = {}
    assert(pathsplit('/single-element', function(ss)
        output[#output + 1] = ss
        return true
    end))
    assert.equal(output, {
        'single-element',
    })

    -- test that split an empty string
    output = {}
    assert(pathsplit('/', function(ss)
        output[#output + 1] = ss
        return true
    end))
    assert.equal(output, {
        '/',
    })

    -- test that split an empty segments
    output = {}
    assert(pathsplit('/foo///bar//baz/', function(ss, s, head, tail)
        assert.equal(s, '/foo///bar//baz/')
        assert.is_int(head)
        assert.is_int(tail)
        assert.less_or_equal(head, tail)
        output[#output + 1] = ss
        return true
    end))
    assert.equal(output, {
        'foo',
        '',
        '',
        'bar',
        '',
        'baz',
        '/',
    })

    -- test that split a string containing a trailing slash
    output = {}
    assert(pathsplit('/one/two/three/four/', function(ss)
        output[#output + 1] = ss
        return true
    end))
    assert.equal(output, {
        'one',
        'two',
        'three',
        'four',
        '/',
    })

    -- test that return an error if pathname is not absolute path
    output = {}
    local ok, err = pathsplit('one/two/three', function(ss)
        output[#output + 1] = ss
        return true
    end)
    assert.is_false(ok)
    assert.equal(err, 'pathname must be absolute path')
    assert.equal(output, {})

    -- test that return an error from callback func
    output = {}
    ok, err = pathsplit('/one/two/three/error/four', function(ss)
        output[#output + 1] = ss
        if ss == 'error' then
            return false, 'Error occurred'
        end
        return true
    end)
    assert.is_false(ok)
    assert.equal(err, 'Error occurred')
    assert.equal(output, {
        'one',
        'two',
        'three',
        'error',
    })
end

