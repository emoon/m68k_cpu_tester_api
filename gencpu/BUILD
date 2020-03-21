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
    srcs = ["table68k"],
    outs = ["cpudefs.cpp"],
    cmd = "$(execpath :build68k) $< > \"$@\"",
    tools = [":build68k"],
)

cc_binary(
    name = "gencpu_prog",
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

genrule(
    name = "gencpu_cpuemu",
    srcs = [],
    outs = [
        "cpuemu_90_test.cpp",
        "cpuemu_91_test.cpp",
        "cpuemu_92_test.cpp",
        "cpuemu_93_test.cpp",
        "cpuemu_94_test.cpp",
        "cpuemu_95_test.cpp",
        "cputbl_test.cpp",
        "cputbl_test.h",
    ],

    cmd = "$(execpath :gencpu_prog) $(RULEDIR)",
    tools = [":gencpu_prog"],
)

cc_binary(
    name = "cputester",
    includes = [".", "include"],
    copts = [
    	"-O2", "-g",
        "-Wno-sign-compare",
    ],
    defines = [
        "CPUEMU_90",
        "CPUEMU_91",
        "CPUEMU_92",
        "CPUEMU_93",
        "CPUEMU_94",
        "CPUEMU_95",
        "CPU_TESTER",
    ],
    srcs = [
        "machdep/rpt.h",
        "machdep/m68k.h",
        "machdep/maccess.h",
        "include/ini.h",
        "include/cpu_prefetch.h",
        "include/cpummu.h",
        "include/cpummu030.h",
        "include/cputest.h",
        "include/custom.h",
        "include/debug.h",
        "include/disasm.h",
        "include/events.h",
        "include/fpp.h",
        "include/mmu_common.h",
        "include/newcpu.h",
        "include/options.h",
        "include/readcpu.h",
        "include/savestate.h",
        "include/sysdeps.h",
        "include/traps.h",
        "include/uae.h",
        "include/uae/attributes.h",
        "include/uae/likely.h",
        "include/uae/time.h",
        "include/uae/types.h",
        "include/uae/vm.h",
        "include/memory.h",
        "include/debugmem.h",
        "cputest/cputest_defines.h",
        "softfloat/softfloat.h",
        "softfloat/softfloat-macros.h",
        "softfloat/softfloat-specialize.h",
        "softfloat/softfloat_fpsp_tables.h",
        "sysconfig.h",
        "target.h",
        "string_wrappers.h",
        ":cpudefs.cpp",
        ":cpuemu_90_test.cpp",
        ":cpuemu_91_test.cpp",
        ":cpuemu_92_test.cpp",
        ":cpuemu_93_test.cpp",
        ":cpuemu_94_test.cpp",
        ":cpuemu_95_test.cpp",
        ":cputbl_test.cpp",
        ":cputbl_test.h",
        "cputest.cpp",
        "cputest_support.cpp",
        "disasm.cpp",
        "fpp.cpp",
        "fpp_softfloat.cpp",
        "ini.cpp",
        "newcpu_common.cpp",
        "readcpu.cpp",
        "softfloat/softfloat.cpp",
        "softfloat/softfloat_decimal.cpp",
        "softfloat/softfloat_fpsp.cpp",
    ],

    deps = ["//zlib:zlib"],
)

