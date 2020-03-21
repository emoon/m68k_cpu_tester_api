load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "m68k_cpu_tester",
    srcs = [
    	# "m68k_cpu_tester.c",
    	"main.c",
    	"m68k_cpu_tester.h",
    	"cputest_defines.h",
    ],

    deps = [
        "//capstone:capstone",
    ],

    visibility = ["//visibility:public"],
)
