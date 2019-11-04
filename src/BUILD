load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "m68k_cpu_tester",
    srcs = [
    	# "adis/decode_ea.c",
    	# "adis/globals.c",
    	# "adis/opcode_handler_cpu.c",
    	# "adis/opcode_handler_fpu.c",
    	# "adis/opcode_handler_mmu.c",
    	# "adis/opcodes_cpu.c",
    	# "adis/opcodes_fpu.c",
    	# "adis/opcodes_mmu.c",
    	# "adis/util.c",
    	# "adis/defs.h",
    	# "adis/string_recog.h",
    	"cpu_tester.c",
    	"cputest_defines.h",
    	"m68k_cputester.h"
    ],

    deps = [
        "//capstone:capstone",
    ],

    visibility = ["//visibility:public"],
)
