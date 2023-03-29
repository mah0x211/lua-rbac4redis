package = "rbac4redis"
version = "scm-1"
source = {
    url = "git+https://github.com/mah0x211/lua-rbac4redis.git",
}
description = {
    summary = "A role-based access control (RBAC) script runs on Redis.",
    homepage = "https://github.com/mah0x211/lua-rbac4redis",
    license = "MIT/X11",
    maintainer = "Masatoshi Fukunaga",
}
dependencies = {
    "lua >= 5.1",
}
build = {
    type = "builtin",
    modules = {
        ['rbac4redis.encode'] = "lib/encode.lua",
        ['rbac4redis.decode'] = "lib/decode.lua",
        ['rbac4redis.merge'] = "lib/merge.lua",
        ['rbac4redis.pathsplit'] = "lib/pathsplit.lua",
    },
}
