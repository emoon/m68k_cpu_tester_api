#include <stdio.h>
#include "lib/m68k_cpu_tester.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void run_68k(void* user_data, const M68KTesterContext* context, M68KTesterRegisters* regs) {}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main() {
    M68KTesterInitResult res;

    M68KTesterRunSettings settings = {0};
    settings.opcode = "MOVE.W";  // notice this is case dependent
    settings.cpu_level = 0;     // 68000

    // Init the tester
    res = M68KTester_init("data", &settings);

    if (res.error) {
        printf("failed to run: %s\n", res.error);
        return 0;
    }

    return M68KTester_run_tests(res.context, NULL, run_68k);
}
