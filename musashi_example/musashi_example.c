#include <stdio.h>
#include <stdlib.h>
#include "lib/m68k_cpu_tester.h"
#include "musashi_example/musashi/m68k.h"

static M68KTesterContext* s_context;

static uint8_t* try_range_to_native(uint32_t addr, uint8_t* ptr, uint32_t start, uint32_t end) {
    if (addr >= start && addr <= end) {
        return ptr + (addr - start);
    } else {
        return 0;
    }
}

static uint8_t* translate_to_native(uint32_t addr) {
	uint8_t* low_memory = s_context->low_memory.buffer;
	uint32_t test_low_memory_start = s_context->low_memory.start;
	uint32_t test_low_memory_end = s_context->low_memory.end;

	uint8_t* high_memory = s_context->high_memory.buffer;
	uint32_t test_high_memory_start = s_context->high_memory.start;
	uint32_t test_high_memory_end = s_context->high_memory.end;

	uint8_t* test_memory = s_context->test_memory.buffer;
	uint32_t test_memory_addr = s_context->test_memory.start;
	uint32_t test_memory_end = s_context->test_memory.end;

    uint8_t* low = try_range_to_native(addr, low_memory, test_low_memory_start, test_low_memory_end);
    uint8_t* high = try_range_to_native(addr, high_memory, test_high_memory_start, test_high_memory_end);
    uint8_t* test = try_range_to_native(addr, test_memory, test_memory_addr, test_memory_end);

    if (low) {
        return low;
    }
    if (high) {
        return high;
    }
    if (test) {
        return test;
    }

    printf("FATAL: %08x was not found within the three memory ranges\n", addr);
    printf("       low_memory (%08x - %08x) %p - %p\n",
                    test_low_memory_start, test_low_memory_start + test_low_memory_end,
                    low_memory, low_memory + test_low_memory_end);
    printf("       high_memory (%08x - %08x) %p - %p\n",
                    test_high_memory_start, test_high_memory_start + test_high_memory_end,
                    high_memory, high_memory + test_high_memory_end);
    printf("       test_memory (%08x - %08x) %p - %p\n",
                    test_memory_addr, test_memory_addr + test_memory_end,
                    test_memory, test_memory + test_memory_end);

    exit(1);

    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define READ_BYTE(BASE, ADDR) (BASE)[ADDR]
#define READ_WORD(BASE, ADDR) (((BASE)[ADDR]<<8) |			\
							  (BASE)[(ADDR)+1])
#define READ_LONG(BASE, ADDR) (((BASE)[ADDR]<<24) |			\
							  ((BASE)[(ADDR)+1]<<16) |		\
							  ((BASE)[(ADDR)+2]<<8) |		\
							  (BASE)[(ADDR)+3])

#define WRITE_BYTE(BASE, ADDR, VAL) (BASE)[ADDR] = (VAL)&0xff
#define WRITE_WORD(BASE, ADDR, VAL) (BASE)[ADDR] = ((VAL)>>8) & 0xff;		\
									(BASE)[(ADDR)+1] = (VAL)&0xff
#define WRITE_LONG(BASE, ADDR, VAL) (BASE)[ADDR] = ((VAL)>>24) & 0xff;		\
									(BASE)[(ADDR)+1] = ((VAL)>>16)&0xff;	\
									(BASE)[(ADDR)+2] = ((VAL)>>8)&0xff;		\
									(BASE)[(ADDR)+3] = (VAL)&0xff

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int m68k_read_memory_8(unsigned int address) {
	uint8_t* v = translate_to_native(address);
	return READ_BYTE(v, 0);
}

unsigned int m68k_read_memory_16(unsigned int address) {
	uint8_t* v = translate_to_native(address);
	return READ_WORD(v, 0);
}

unsigned int m68k_read_memory_32(unsigned int address) {
	unsigned int v0 = m68k_read_memory_16((address + 0) & 0x00ffffff);
	unsigned int v1 = m68k_read_memory_16((address + 2) & 0x00ffffff);
	return (v0 << 16)  | v1;
}

void m68k_write_memory_8(unsigned int address, unsigned int v) {
	uint8_t* d = translate_to_native(address);
	WRITE_BYTE(d, 0, v);
}

void m68k_write_memory_16(unsigned int address, unsigned int v) {
	uint8_t* d = translate_to_native(address);
	WRITE_WORD(d, 0, v);
}

void m68k_write_memory_32(unsigned int address, unsigned int v) {
	// TODO: Fix hard-coding for 68000
	m68k_write_memory_16((address + 0) & 0x00ffffff, v >> 16);
	m68k_write_memory_16((address + 2) & 0x00ffffff, v & 0xffff);
}

unsigned int m68k_read_disassembler_16(unsigned address) {
	return m68k_read_memory_16(address);
}

unsigned int m68k_read_disassembler_32(unsigned address) {
	return m68k_read_memory_32(address);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void run_68k(void* user_data, const M68KTesterContext* context, M68KTesterRegisters* regs) {
	for (int i = 0; i < 16; ++i) {
		m68k_set_reg(M68K_REG_D0 + i, regs->regs[i]);
	}

	m68k_set_reg(M68K_REG_PC, regs->pc);
	m68k_set_reg(M68K_REG_SP, regs->regs[15]);
	m68k_set_reg(M68K_REG_SR, regs->sr);
	//m68k_set_reg(M68K_REG_MSP, regs->msp);
	//m68k_set_reg(M68K_REG_ISP, regs->ssp);	// not sure if this is correct

	do {
		m68k_execute(4);
	} while (regs->pc == m68k_get_reg(0, M68K_REG_PC));

	for (int i = 0; i < 16; ++i) {
		regs->regs[i] = m68k_get_reg(0, M68K_REG_D0 + i);
	}

	regs->pc = m68k_get_reg(0, M68K_REG_PC);
	regs->sr = m68k_get_reg(0, M68K_REG_SR);
	//regs->msp = m68k_get_reg(0, M68K_REG_MSP);
	//regs->ssp = m68k_get_reg(0, M68K_REG_ISP);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main() {
    M68KTesterInitResult res;

    M68KTesterRunSettings settings = {0};
    //settings.opcode = "all";  // notice this is case dependent
    settings.opcode = "ADD.W";  // notice this is case dependent
    settings.cpu_level = 0;     // 68000

    // Init the tester
    res = M68KTester_init("data/68000_Basic", &settings);

    if (res.error) {
        printf("failed to run: %s\n", res.error);
        return 0;
    }

    m68k_init();
	m68k_set_cpu_type(M68K_CPU_TYPE_68000);

	s_context = res.context;

    return M68KTester_run_tests(res.context, NULL, run_68k);

	return 0;
}

