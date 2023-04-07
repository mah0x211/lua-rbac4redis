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
        ["rbac4redis.set"] = "lib/set.lua",
        ["rbac4redis.del"] = "lib/del.lua",
        ["rbac4redis.list"] = "lib/list.lua",
        ["rbac4redis.search"] = "lib/search.lua",
        ["rbac4redis.dump"] = "lib/dump.lua",
        ["rbac4redis.encode"] = "lib/encode.lua",
        ["rbac4redis.decode"] = "lib/decode.lua",
        ["rbac4redis.merge"] = "lib/merge.lua",
        ["rbac4redis.pathsplit"] = "lib/pathsplit.lua",
        ["rbac4redis.redis"] = "lib/redis.lua",
    },
}
