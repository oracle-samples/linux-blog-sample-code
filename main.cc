/*
 * Copyright (c) 2020, Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 * (b) any piece of software and/or hardware listed in the
 *     lrgrwrks.txt file if one is included with the Software (each a "Larger
 *     Work" to which the Software is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition: The above copyright notice
 * and either this complete permission notice or at a minimum a reference to the
 * UPL must be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Author: Vegard Nossum <vegard.nossum@oracle.com>
// build with: g++ -std=c++14 -Wall -O2 -static -o entry-fuzz main.cc

#include <asm/ldt.h>
#include <asm/prctl.h>

#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <assert.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <random>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

static std::default_random_engine rnd;

typedef void (*generated_code_fn)(void);

static void *mem;

struct ljmp_target {
    uint32_t rip;
    uint16_t cs;
} __attribute__((packed));

struct data {
    uint64_t saved_rsp;

    struct ljmp_target ljmp;

    // ENTRY_BR
    struct {
        uint32_t lower;
        uint32_t upper;
    } bound;
};

static struct data *data;

static void *page_not_present;
static void *page_not_writable;
static void *page_not_executable;

static uint64_t get_random_address()
{
    // very occasionally hand out a non-canonical address
    if (std::uniform_int_distribution<int>(0, 100)(rnd) < 5)
        return 1UL << 63;

    uint64_t value = 0;

    switch (std::uniform_int_distribution<int>(0, 4)(rnd)) {
    case 0:
        break;
    case 1:
        value = (uint64_t) page_not_present;
        break;
    case 2:
        value = (uint64_t) page_not_writable;
        break;
    case 3:
        value = (uint64_t) page_not_executable;
        break;
    case 4:
        static const uint64_t kernel_pointers[] = {
            0xffffffff81000000UL,
            0xffffffff82016000UL,
            0xffffffffc0002000UL,
            0xffffffffc2000000UL,
        };

        value = kernel_pointers[std::uniform_int_distribution<int>(0, ARRAY_SIZE(kernel_pointers))(rnd)];

        // random ~2MiB offset
        value += PAGE_SIZE * std::uniform_int_distribution<unsigned int>(0, 512)(rnd);
        break;
    }

    // occasionally intentionally misalign it
    if (std::uniform_int_distribution<int>(0, 100)(rnd) < 25)
        value += std::uniform_int_distribution<int>(-7, 7)(rnd);

    return value;
}

static uint16_t get_random_segment_selector()
{
#if 0
    unsigned int index;

    switch (std::uniform_int_distribution<unsigned int>(0, 2)(rnd)) {
    case 0:
        // The LDT is small, so favour smaller indices
        index = std::uniform_int_distribution<unsigned int>(0, 3)(rnd);
        break;
    case 1:
        // Linux defines 32 GDT entries by default
        index = std::uniform_int_distribution<unsigned int>(0, 31)(rnd);
        break;
    case 2:
        // Max table size
        index = std::uniform_int_distribution<unsigned int>(0, 255)(rnd);
        break;
    }
    unsigned int ti = std::uniform_int_distribution<unsigned int>(0, 1)(rnd);
    unsigned int rpl = std::uniform_int_distribution<unsigned int>(0, 3)(rnd);

    return (index << 3) | (ti << 2) | rpl;
#else
    // only valid segment selectors
    switch (std::uniform_int_distribution<unsigned int>(0, 2)(rnd)) {
    case 0:
        // USER32_CS
        return (4 << 3) | 3;
    case 1:
        // USER_DS
        return (5 << 3) | 3;
    case 2:
        // USER_CS
        return (6 << 3) | 3;
    default:
        assert(false);
    }
#endif
}

static uint8_t *emit_save_rsp(uint8_t *out)
{
    // mov %rsp, (addr)
    *out++ = 0x48;
    *out++ = 0x89;
    *out++ = 0x24;
    *out++ = 0x25;
    for (int i = 0; i < 4; ++i)
        *out++ = ((uint64_t) &data->saved_rsp) >> (8 * i);

    return out;
}

static uint8_t *emit_restore_rsp(uint8_t *out)
{
    // mov (addr), %rsp
    *out++ = 0x48;
    *out++ = 0x8b;
    *out++ = 0x24;
    *out++ = 0x25;
    for (int i = 0; i < 4; ++i)
        *out++ = ((uint64_t) &data->saved_rsp) >> (8 * i);

    return out;
}

static uint8_t *emit_rsp(uint8_t *out)
{
    uint64_t rsp = get_random_address();

    // movq $imm, %rsp
    *out++ = 0x48;
    *out++ = 0xbc;
    for (int i = 0; i < 8; ++i)
        *out++ = rsp >> (8 * i);

    return out;
}

static uint8_t *emit_rflags(uint8_t *out)
{
    // pushfq
    *out++ = 0x9c;

    uint32_t mask = 0;

    // trap flag
    mask |= std::uniform_int_distribution<unsigned int>(0, 1)(rnd) << 8;

    // direction flag
    mask |= std::uniform_int_distribution<unsigned int>(0, 1)(rnd) << 10;

    // alignment check
    mask |= std::uniform_int_distribution<unsigned int>(0, 1)(rnd) << 18;

    // xorq $mask, 0(%rsp)
    *out++ = 0x48;
    *out++ = 0x81;
    *out++ = 0x34;
    *out++ = 0x24;
    *out++ = mask;
    *out++ = mask >> 8;
    *out++ = mask >> 16;
    *out++ = mask >> 24;

    // popfq
    *out++ = 0x9d;

    return out;
}

static uint8_t *emit_restore_rflags(uint8_t *out)
{
    // pushfq
    *out++ = 0x9c;

    // andq $0xfffffffffffbfaff, 0(%rsp)
    *out++ = 0x48;
    *out++ = 0x81;
    *out++ = 0x24;
    *out++ = 0x24;
    *out++ = 0xff;
    *out++ = 0xfa;
    *out++ = 0xfb;
    *out++ = 0xff;

    // popfq
    *out++ = 0x9d;

    return out;
}

static uint8_t *emit_ds(uint8_t *out)
{
    uint16_t sel = get_random_segment_selector();

    // movw $imm, %ax
    *out++ = 0x66;
    *out++ = 0xb8;
    *out++ = sel;
    *out++ = sel >> 8;

    // movw %ax, %ds
    *out++ = 0x8e;
    *out++ = 0xd8;

    return out;
}

static uint8_t *emit_ss(uint8_t *out)
{
    uint16_t sel = get_random_segment_selector();

    // movw $imm, %cx
    *out++ = 0x66;
    *out++ = 0xb9;
    *out++ = sel;
    *out++ = sel >> 8;

    // movw %cx, %ss
    *out++ = 0x8e;
    *out++ = 0xd1;

    return out;
}

static uint8_t *emit_cs(uint8_t *out)
{
    uint16_t sel = get_random_segment_selector();

    // ljmp *target
    *out++ = 0xff;
    *out++ = 0x2c;
    *out++ = 0x25;
    for (unsigned int i = 0; i < 4; ++i)
        *out++ = ((uint64_t) &data->ljmp) >> (8 * i);

    data->ljmp.cs = sel;
    data->ljmp.rip = (uint64_t) out;

    return out;
}

enum machine_register {
    // 0
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    // 8
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
};

const unsigned int REX = 0x40;
const unsigned int REX_B = 0x01;
const unsigned int REX_W = 0x08;

static uint8_t *emit_mov_imm64_reg(uint8_t *out, uint64_t imm, machine_register reg)
{
    *out++ = REX | REX_W | (REX_B * (reg >= 8));
    *out++ = 0xb8 | (reg & 7);
    for (int i = 0; i < 8; ++i)
        *out++ = imm >> (8 * i);

    return out;
}

static uint8_t *emit_call_arch_prctl(uint8_t *out, int code, unsigned long addr)
{
    // int arch_prctl(int code, unsigned long addr);
    out = emit_mov_imm64_reg(out, SYS_arch_prctl, RAX);
    out = emit_mov_imm64_reg(out, code, RDI);
    out = emit_mov_imm64_reg(out, addr, RSI);

    // syscall
    *out++ = 0x0f;
    *out++ = 0x05;

    return out;
}

enum entry_type {
    // system calls + software interrupts
    ENTRY_SYSCALL,
    ENTRY_SYSENTER,
    ENTRY_INT,
    ENTRY_INT_80,
    ENTRY_INT3,

    // exceptions
    ENTRY_DE, // Divide error
    ENTRY_OF, // Overflow
    ENTRY_BR, // Bound range exceeded
    ENTRY_UD, // Undefined opcode
    ENTRY_SS, // Stack segment fault
    ENTRY_GP, // General protection fault
    ENTRY_PF, // Page fault
    ENTRY_MF, // x87 floating-point exception
    ENTRY_AC, // Alignment check

    NR_ENTRY_TYPES,
};

static uint8_t *emit_code()
{
    uint8_t *out = (uint8_t *) mem;

    out = emit_save_rsp(out);

    for (int i = 0; i < 10; ++i) {
        // restore %rsp before changing %rflags, since the latter needs a
        // valid stack in order not to crash
        out = emit_restore_rsp(out);

        out = emit_call_arch_prctl(out, ARCH_SET_FS, get_random_address());
        out = emit_call_arch_prctl(out, ARCH_SET_GS, get_random_address());

        out = emit_rflags(out);
        out = emit_rsp(out);

        if (std::uniform_int_distribution<unsigned int>(0, 100)(rnd) < 20)
            out = emit_ds(out);

        if (std::uniform_int_distribution<unsigned int>(0, 100)(rnd) < 20)
            out = emit_cs(out);

        enum entry_type type = (enum entry_type) std::uniform_int_distribution<int>(0, NR_ENTRY_TYPES - 1)(rnd);

        // Some entry types require a setup/preamble; do that here
        switch (type) {
        case ENTRY_SYSCALL:
        case ENTRY_SYSENTER:
        case ENTRY_INT:
        case ENTRY_INT_80:
            // pick a system call number that we know won't block across
            // x86_64, i386, and x64 ABIs.

            // 96 is getpriority() on i386 and gettimeofday() on x86_64/x64
            *out++ = 0xb8;
            *out++ = 0x60;
            *out++ = 0x00;
            *out++ = 0x00;
            *out++ = 0x00;
            break;

        case ENTRY_DE:
            // xor %eax, %eax
            *out++ = 0x31;
            *out++ = 0xc0;
            break;
        case ENTRY_MF:
            // pxor %xmm0, %xmm0
            *out++ = 0x66;
            *out++ = 0x0f;
            *out++ = 0xef;
            *out++ = 0xc0;
            break;
        case ENTRY_BR:
            // xor %eax, %eax
            *out++ = 0x31;
            *out++ = 0xc0;
            break;
        case ENTRY_SS:
            {
                uint16_t sel = get_random_segment_selector();

                // movw $imm, %bx
                *out++ = 0x66;
                *out++ = 0xbb;
                *out++ = sel;
                *out++ = sel >> 8;
            }
            break;
        default:
            break;
        }

        if (std::uniform_int_distribution<unsigned int>(0, 100)(rnd) < 20)
            out = emit_ss(out);

        switch (type) {
            // system calls + software interrupts

        case ENTRY_SYSCALL:
            // syscall
            *out++ = 0x0f;
            *out++ = 0x05;
            break;
        case ENTRY_SYSENTER:
            // sysenter
            *out++ = 0x0f;
            *out++ = 0x34;
            break;
        case ENTRY_INT:
            {
                // just make sure we don't take the 'int $0x80' since this is
                // an actual system call 
                uint8_t x = std::uniform_int_distribution<uint8_t>(0, 254)(rnd);
                if (x == 0x80)
                    ++x;

                // int $x
                *out++ = 0xcd;
                *out++ = x;
            }
            break;
        case ENTRY_INT_80:
            // int $0x80
            *out++ = 0xcd;
            *out++ = 0x80;
            break;
        case ENTRY_INT3:
            // int3
            *out++ = 0xcc;
            break;

            // exceptions

        case ENTRY_DE:
            // div %eax
            *out++ = 0xf7;
            *out++ = 0xf0;
            break;
        case ENTRY_OF:
            // into (32-bit only!)
            *out++ = 0xce;
            break;
        case ENTRY_BR:
            // bound %eax, data
            *out++ = 0x62;
            *out++ = 0x05;
            *out++ = 0x09;
            for (unsigned int i = 0; i < 4; ++i)
                *out++ = ((uint64_t) &data->bound) >> (8 * i);
            break;
        case ENTRY_UD:
            // ud2
            *out++ = 0x0f;
            *out++ = 0x0b;
            break;
        case ENTRY_SS:
            // Load %ss again, with a random segment selector (this is not
            // guaranteed to raise #SS, but most likely it will). The reason
            // we don't just rely on the load above to do it is that it could
            // be interesting to trigger #SS with a "weird" %ss too.

            // movw %bx, %ss
            *out++ = 0x8e;
            *out++ = 0xd3;
            break;
        case ENTRY_GP:
            // wrmsr
            *out++ = 0x0f;
            *out++ = 0x30;
            break;
        case ENTRY_PF:
            // testl %eax, (xxxxxxxx)
            *out++ = 0x85;
            *out++ = 0x04;
            *out++ = 0x25;
            for (unsigned int i = 0; i < 4; ++i)
                *out++ = ((uint64_t) page_not_present) >> (8 * i);
            break;
        case ENTRY_MF:
            // divss %xmm0, %xmm0
            *out++ = 0xf3;
            *out++ = 0x0f;
            *out++ = 0x5e;
            *out++ = 0xc0;
            break;
        case ENTRY_AC:
            // testl %eax, (page_not_writable + 1)
            *out++ = 0x85;
            *out++ = 0x04;
            *out++ = 0x25;
            for (unsigned int i = 0; i < 4; ++i)
                *out++ = ((uint64_t) page_not_writable + 1) >> (8 * i);
            break;
        default:
            assert(false);
        }
    }

    out = emit_restore_rsp(out);
    out = emit_restore_rflags(out);

    // retq
    *out++ = 0xc3;

    return out;
}

static void handle_child_sigtrap(int signum, siginfo_t *siginfo, void *ucontext)
{
    // this gets called when TF is set in %rflags; do nothing
}

static void handle_child_sigsegv(int signum, siginfo_t *siginfo, void *ucontext)
{
        // disable single-stepping, direction flag, and alignment checking if they were enabled
        asm volatile ("pushfq; andq $~((1 << 8) | (1 << 10) | (1 << 18)), 0(%%rsp); popfq" : : : "cc");
        _exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    if (getpid() == 1) {
            // If we're init (pid 1), do some init duties.
            mkdir("/proc", 0777);
            mount("nodev", "/proc", "proc", 0, "");
            mkdir("/sys", 0777);
            mount("nodev", "/sys", "sysfs", 0, "");
            mkdir("/dev", 0777);
            mount("nodev", "/dev", "devtmpfs", 0, "");
    }

    std::random_device rdev;
    rnd = std::default_random_engine(rdev());

    // 16 pages is just a conservative estimate
    mem = mmap(NULL, 2 * PAGE_SIZE,
        // prot
        PROT_READ | PROT_WRITE | PROT_EXEC,
        // flags
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
        // fd, offset
        -1, 0);
    if (mem == MAP_FAILED)
        error(EXIT_FAILURE, errno, "mmap()");

    {
        void *addr = mmap(NULL, PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
            -1, 0);
        if (addr == MAP_FAILED)
            error(EXIT_FAILURE, errno, "mmap()");

        data = (struct data *) addr;
        data->bound.lower = 0;
        data->bound.upper = 0;
    }

    page_not_present = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    page_not_writable = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    page_not_executable = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);

    printf("code = %p\n", mem);
    printf("data = %p\n", data);
    printf("page_not_present = %p\n", page_not_present);
    printf("page_not_writable = %p\n", page_not_writable);
    printf("page_not_executable = %p\n", page_not_executable);

    {
       stack_t ss = {};

       ss.ss_sp = malloc(SIGSTKSZ);
       if (ss.ss_sp == NULL)
            error(EXIT_FAILURE, errno, "malloc()");

       ss.ss_size = SIGSTKSZ;
       ss.ss_flags = 0;
       if (sigaltstack(&ss, NULL) == -1)
            error(EXIT_FAILURE, errno, "sigaltstack()");
    }

    unsigned int nr_total = 0;
    unsigned int nr_success = 0;

    unsigned int nr_iterations = 0;

    struct timeval start_tv;
    if (gettimeofday(&start_tv, 0) == -1)
        error(EXIT_FAILURE, errno, "gettimeofday()");

    while (1) {
        uint8_t *out = emit_code();

        pid_t child = fork();
        if (child == -1)
            error(EXIT_FAILURE, errno, "fork()");

        if (child == 0) {
            // we're the child

            // make us a tracee of the parent
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
                error(EXIT_FAILURE, errno, "ptrace(PTRACE_TRACEME)");

            // give the parent control
            raise(SIGTRAP);

            struct sigaction sigtrap_act = {};
            sigtrap_act.sa_sigaction = &handle_child_sigtrap;
            sigtrap_act.sa_flags = SA_SIGINFO | SA_ONSTACK;
            if (sigaction(SIGTRAP, &sigtrap_act, NULL) == -1)
                error(EXIT_FAILURE, errno, "sigaction(SIGTRAP)");

            struct sigaction sigsegv_act = {};
            sigsegv_act.sa_sigaction = &handle_child_sigsegv;
            sigsegv_act.sa_flags = SA_SIGINFO | SA_ONSTACK;
            if (sigaction(SIGSEGV, &sigsegv_act, NULL) == -1)
                error(EXIT_FAILURE, errno, "sigaction(SIGSEGV)");

            // TODO
            if (sigaction(SIGILL, &sigsegv_act, NULL) == -1)
                error(EXIT_FAILURE, errno, "sigaction(SIGSEGV)");
            if (sigaction(SIGFPE, &sigsegv_act, NULL) == -1)
                error(EXIT_FAILURE, errno, "sigaction(SIGSEGV)");
            if (sigaction(SIGBUS, &sigsegv_act, NULL) == -1)
                error(EXIT_FAILURE, errno, "sigaction(SIGSEGV)");

            for (unsigned int i = 0; i < 4; ++i) {
                struct user_desc desc = {};
                desc.entry_number = i;
                desc.base_addr = std::uniform_int_distribution<unsigned long>(0, ULONG_MAX)(rnd);
                desc.limit = std::uniform_int_distribution<unsigned int>(0, UINT_MAX)(rnd);
                desc.seg_32bit = std::uniform_int_distribution<int>(0, 1)(rnd);
                desc.contents = std::uniform_int_distribution<int>(0, 3)(rnd);
                desc.read_exec_only = std::uniform_int_distribution<int>(0, 1)(rnd);
                desc.limit_in_pages = std::uniform_int_distribution<int>(0, 1)(rnd);
                desc.seg_not_present = std::uniform_int_distribution<int>(0, 1)(rnd);
                desc.useable = std::uniform_int_distribution<int>(0, 1)(rnd);

                syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));
            }

            ((generated_code_fn) mem)();

            exit(EXIT_SUCCESS);
        }

        // we're the parent; wait for child to stop
        while (1) {
            int status;
            if (waitpid(child, &status, 0) == -1) {
                if (errno == EINTR)
                    continue;

                error(EXIT_FAILURE, errno, "waitpid()");
            }

            if (WIFEXITED(status))
                exit(WEXITSTATUS(status));
            if (WIFSIGNALED(status))
                exit(EXIT_FAILURE);

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
                break;
        }

        // stddef.h offsetof() doesn't always allow non-const array indices,
        // so precompute them here.
        const unsigned int debugreg_offsets[] = {
            offsetof(struct user, u_debugreg[0]),
            offsetof(struct user, u_debugreg[1]),
            offsetof(struct user, u_debugreg[2]),
            offsetof(struct user, u_debugreg[3]),
        };

        for (unsigned int i = 0; i < 4; ++i) {
            while (true) {
                unsigned long addr = get_random_address();
                if (ptrace(PTRACE_POKEUSER, child, debugreg_offsets[i], addr) != -1)
                    break;
            }

            // Condition:
            // 0 - execution
            // 1 - write
            // 2 - (unused)
            // 3 - read or write
            unsigned int condition = std::uniform_int_distribution<unsigned int>(0, 2)(rnd);
            if (condition == 2)
                condition = 3;

            // Size
            // 0 - 1 byte
            // 1 - 2 bytes
            // 2 - 8 bytes
            // 3 - 4 bytes
            unsigned int size = std::uniform_int_distribution<unsigned int>(0, 3)(rnd);

            unsigned long dr7 = ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg[7]), 0);
            dr7 &= ~((1 | (3 << 16) | (3 << 18)) << i);
            dr7 |= (1 | (condition << 16) | (size << 18)) << i;
            ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[7]), dr7);
        }

        // detach
        if (ptrace(PTRACE_DETACH, child, 0, 0) == -1)
            error(EXIT_FAILURE, errno, "ptrace(PTRACE_DETACH)");

        // wait for the child to exit
        while (1) {
            int status;
            if (waitpid(child, &status, 0) == -1) {
                if (errno == EINTR)
                    continue;

                error(EXIT_FAILURE, errno, "waitpid()");
            }

            nr_total += 1;
            nr_success += (WIFEXITED(status) && WEXITSTATUS(status) == 0);

            break;
        }

        ++nr_iterations;

        struct timeval end_tv;
        if (gettimeofday(&end_tv, 0) == -1)
                error(EXIT_FAILURE, errno, "gettimeofday()");

        struct timeval delta_tv;
        timersub(&end_tv, &start_tv, &delta_tv);

        if (delta_tv.tv_sec <= 0)
                continue;

        // Status line
        printf("%.2f it/sec | %u / %u\n", nr_iterations / (delta_tv.tv_sec + delta_tv.tv_usec / 1e6), nr_total, nr_success);

        nr_iterations = 0;
        start_tv = end_tv;
    }

    return 0;
}
