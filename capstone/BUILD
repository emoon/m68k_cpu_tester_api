load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "capstone",
    copts = ["-DCAPSTONE_USE_SYS_DYN_MEM", "-DCAPSTONE_HAS_M68K"],
    srcs = glob(["*.c", "arch/M68K/*.c", "arch/M68K/*.inc", "*.h", "include/capstone/*.h", "arch/M68K/*.h"]),
    hdrs = ["include/capstone/capstone.h"],
    # hdrs = glob(["*.h", "include/capstone/*.h", "arch/M68K/*.h", "include/capstone/capstone.h"]),
    visibility = ["//visibility:public"],
)

