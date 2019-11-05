load("@rules_cc//cc:defs.bzl", "cc_binary")

# cc_binary(
# 	name = "m68k_make",
# 	srcs = ["musashi/m68kmake.c", "musashi/m68k_in.h"],
#)

# genrule(
#    name = "gen_musashi_code",
#    srcs = ["musashi/m68k_in.h"],
#    outs = ["m68kops.c", "m68kops.h"],
#    cmd = "./$(location m68k_make) $(location) $(location)/m68k_in.h",
#    tools = ["m68k_make"],
#)

cc_binary(
	name = "musashi_example",
	srcs = [
		# "m68kops.c",
		# "m68kops.h",
		"musashi/m68kops.c",
		"musashi/m68kops.h",
		"musashi/m68kconf.h",
		"musashi/m68kcpu.h",
		"musashi/m68k.h",
		"musashi/m68kcpu.c",
		"musashi/m68kdasm.c",
		"musashi/m68kfpu.c",
		"musashi_example.c",
	],

    deps = [
        "//capstone:capstone",
        "//lib:m68k_cpu_tester",
    ],
)

