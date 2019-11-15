# m68k_cpu_tester_api

This repo makes an API around the cpu tester from WinUAE that can be found [here](https://github.com/tonioni/WinUAE/tree/master/cputest) with more info. The cputester in WinUAE is mainly built to run as an executable on Amiga but what this does is wraps the tester and allows it to be used for other use-cases such as emulators or test-beds for FPGA implementations.

Usage:

# Dependencies

1. To compile the code you need [Bazel](https://bazel.build) but the rules are simple so moving the code to any other build system should be straightforward.
2. In order to run the code you need to generate the tests by an unpacking this [file](https://github.com/emoon/m68k_cpu_tester_api/blob/master/cputester.7z)

# Testing the Musashi example

1. Build the Musashi example using this command: `bazel build //musashi_example:musashi_example`
2. Unpack the tester exe `7z x cputester.7z -ocputester`
   * `cd cputester`
   * cputester.exe (on Linux `wine` cputester.exe works fine also)
   * `move/mv data ..`
   * `cd ..`
3. Run `bazel-bin/musashi_example/musashi_example`

# Known issues

Currently the test will break when trying to execute the `JMP` instruction,

```
data/68000/JMP/0000.dat. 0...
restore_rel CT_ABSOLUTE_LONG outside of test memory! 7fff8036
Last test: 168
 4ef1 6fb7
```
