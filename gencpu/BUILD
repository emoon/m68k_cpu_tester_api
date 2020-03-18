load("@rules_cc//cc:defs.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "build68k",
    includes = [".", "include"],
    srcs = [
        "sysconfig.h",
        "target.h",
        "include/sysdeps.h",
        "include/readcpu.h",
        "include/uae/types.h",
        "build68k.cpp"
    ],
)

genrule(
    name = "build68k_cpudefs",
    srcs = [],
    outs = ["cpudefs.cpp"],
    cmd = "$(execpath :build68k) < table68k > \"$@\"",
    tools = [":build68k"],
)

cc_binary(
    name = "gencpu",
    includes = [".", "include"],
    srcs = [
        "sysconfig.h",
        "target.h",
        "include/sysdeps.h",
        "include/readcpu.h",
        "include/uae.h",
        "include/uae/types.h",
        ":cpudefs.cpp",
        "gencpu.cpp",
        "missing.cpp",
        "readcpu.cpp",
    ],
)



