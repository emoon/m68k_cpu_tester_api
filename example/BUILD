load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
	name = "example",
	srcs = ["example.c"],
    deps = [
        "//capstone:capstone",
        "//src:m68k_cpu_tester",
    ],
)
