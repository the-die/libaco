// Copyright 2018 Sen Han <00hnes@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ACO_H
#define ACO_H

#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>

#ifdef ACO_USE_VALGRIND
    #include <valgrind/valgrind.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// https://semver.org/spec/v2.0.0.html
#define ACO_VERSION_MAJOR 1
#define ACO_VERSION_MINOR 2
#define ACO_VERSION_PATCH 4

/*
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
 * +---+---+---+---+---+---+---+---+
 *  RET  SP  BP             FPU
 *
 * +-------+-------+-------+-------+-------+-------+-------+-------+-------+
 * |   0   |   1   |   2   |   3   |   4   |   5   |   6   |   7   |   8   |
 * +-------+-------+-------+-------+-------+-------+-------+-------+-------+
 *                                    RET      SP              BP     FPU
 */

#ifdef __i386__
    #define ACO_REG_IDX_RETADDR 0
    #define ACO_REG_IDX_SP 1
    #define ACO_REG_IDX_BP 2
    #define ACO_REG_IDX_FPU 6
#elif __x86_64__
    #define ACO_REG_IDX_RETADDR 4
    #define ACO_REG_IDX_SP 5
    #define ACO_REG_IDX_BP 7
    #define ACO_REG_IDX_FPU 8
#else
    #error "platform no support yet"
#endif

// private stack
typedef struct {
    void*  ptr;
    size_t sz;
    size_t valid_sz;

    // The following variables are used for performance tracking.

    // max copy size in bytes
    size_t max_cpsz;
    // copy from share stack to this save stack
    size_t ct_save;
    // copy from this save stack to share stack 
    size_t ct_restore;
} aco_save_stack_t;

struct aco_s;
typedef struct aco_s aco_t;

/*
 * guard_page_enabled: 1
 * highptr: align to 16 bytes
 *
 * high
 *  |            +-----------------+         ^    ^
 *  |            |                 |         |    |
 *  | highptr -> +-----------------+         |    |
 *  |            |    protector    |         |    |
 *  |  retptr -> +-----------------+         | sz |
 *  |            |                 |         |    | real_sz
 *  |            |                 |         |    |
 *  |            |                 |         |    |
 *  |            +-----------------+ <- ptr  v    |
 *  |            |                 |              |
 *  |            +-----------------+ <- realptr   v
 *  v
 * low
 */

typedef struct {
    void*  ptr;
    size_t sz;
    void*  align_highptr; // stack top
    void*  align_retptr;  // return address
    size_t align_validsz; // stack size
    size_t align_limit;   // stack limit
    aco_t* owner;

    char guard_page_enabled;
    void* real_ptr;
    size_t real_sz;

#ifdef ACO_USE_VALGRIND
    unsigned long valgrind_stk_id;
#endif
} aco_share_stack_t;

typedef void (*aco_cofuncp_t)(void);

struct aco_s{
    // cpu registers' state
#ifdef __i386__
    #ifdef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        void*  reg[6];
    #else
        void*  reg[8];
    #endif
#elif __x86_64__
    #ifdef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        void*  reg[8];
    #else
        void*  reg[9];
    #endif
#else
    #error "platform no support yet"
#endif
    aco_t* main_co;
    char   is_end;

    aco_cofuncp_t fp;
    void*  arg;

    aco_save_stack_t  save_stack;
    aco_share_stack_t* share_stack;
};

// https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
// __builtin_expect

#define aco_likely(x) (__builtin_expect(!!(x), 1))

#define aco_unlikely(x) (__builtin_expect(!!(x), 0))

#define aco_assert(EX)  ((aco_likely(EX))?((void)0):(abort()))

#define aco_assertptr(ptr)  ((aco_likely((ptr) != NULL))?((void)0):(abort()))

#define aco_assertalloc_bool(b)  do {  \
    if(aco_unlikely(!(b))){    \
        fprintf(stderr, "Aborting: failed to allocate memory: %s:%d:%s\n", \
            __FILE__, __LINE__, __PRETTY_FUNCTION__);    \
        abort();    \
    }   \
} while(0)

#define aco_assertalloc_ptr(ptr)  do {  \
    if(aco_unlikely((ptr) == NULL)){    \
        fprintf(stderr, "Aborting: failed to allocate memory: %s:%d:%s\n", \
            __FILE__, __LINE__, __PRETTY_FUNCTION__);    \
        abort();    \
    }   \
} while(0)

#if defined(aco_attr_no_asan)
    #error "aco_attr_no_asan already defined"
#endif
#if defined(ACO_USE_ASAN)
    // https://clang.llvm.org/docs/LanguageExtensions.html
    // https://clang.llvm.org/docs/AddressSanitizer.html
    // https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
    // https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
    #if defined(__has_feature)
        #if __has_feature(address_sanitizer)
            #define aco_attr_no_asan \
                __attribute__((no_sanitize_address))
        #endif
    #endif
    #if defined(__SANITIZE_ADDRESS__) && !defined(aco_attr_no_asan)
        #define aco_attr_no_asan \
            __attribute__((no_sanitize_address))
    #endif
#endif
#ifndef aco_attr_no_asan
    #define aco_attr_no_asan
#endif

extern void aco_runtime_test(void);

// Initializes the libaco environment in the current thread.
//
// It will store the current control words of FPU and MXCSR into a thread-local global variable.

// If the global macro ACO_CONFIG_SHARE_FPU_MXCSR_ENV is not defined, the saved control words would
// be used as a reference value to set up the control words of the new co's FPU and MXCSR
// (in aco_create) and each co would maintain its own copy of FPU and MXCSR control words during
// later context switching.
// If the global macro ACO_CONFIG_SHARE_FPU_MXCSR_ENV is defined, then all the co shares the same
// control words of FPU and MXCSR. 
extern void aco_thread_init(aco_cofuncp_t last_word_co_fp);

// https://gcc.gnu.org/onlinedocs/gcc/Asm-Labels.html

extern void* acosw(aco_t* from_co, aco_t* to_co) __asm__("acosw"); // asm

// Store x87 FPU control word and store the contents of the MXCSR control and status register
extern void aco_save_fpucw_mxcsr(void* p) __asm__("aco_save_fpucw_mxcsr");  // asm

extern void aco_funcp_protector_asm(void) __asm__("aco_funcp_protector_asm"); // asm

extern void aco_funcp_protector(void);

// Equal to aco_share_stack_new2(sz, 1).
extern aco_share_stack_t* aco_share_stack_new(size_t sz);

// Creates a new share stack with a advisory memory size of sz in bytes and may have a guard page
// (read-only) for the detection of stack overflow which is depending on the 2nd argument
// guard_page_enabled.
aco_share_stack_t* aco_share_stack_new2(size_t sz, char guard_page_enabled);

// Destory the share stack sstk.
//
// Be sure that all the co whose share stack is sstk is already destroyed when you destroy the sstk.
extern void aco_share_stack_destroy(aco_share_stack_t* sstk);

// Create a new co.
//
// If it is a main_co you want to create, just call: aco_create(NULL, NULL, 0, NULL, NULL). Main co
// is a special standalone coroutine whose share stack is the default thread stack. In the thread,
// main co is the coroutine who should be created and started to execute before all the other
// non-main coroutine does.
extern aco_t* aco_create(
        aco_t* main_co,
        aco_share_stack_t* share_stack, 
        size_t save_stack_sz, 
        aco_cofuncp_t fp, void* arg
    );

// aco's Global Thread Local Storage variable `co`
extern __thread aco_t* aco_gtls_co;

// Yield from the caller main co and to start or continue the execution of co.
// 
// The caller of this function must be a main co and must be co->main_co. And the 1st argument co
// must be a non-main co.
//
// The first time you resume a co, it starts running the function pointing by co->fp. If co has
// already been yielded, aco_resume restarts it and continues the execution.
aco_attr_no_asan
extern void aco_resume(aco_t* resume_co);

//extern void aco_yield1(aco_t* yield_co);
#define aco_yield1(yield_co) do {             \
    aco_assertptr((yield_co));                    \
    aco_assertptr((yield_co)->main_co);           \
    acosw((yield_co), (yield_co)->main_co);   \
} while(0)

// Yield the execution of co and resume co->main_co. The caller of this function must be a non-main
// co. And co->main_co must not be NULL.
#define aco_yield() do {        \
    aco_yield1(aco_gtls_co);    \
} while(0)

// Equal to (aco_get_co()->arg). And also, the caller of this function must be a non-main co.
#define aco_get_arg() (aco_gtls_co->arg)

// Return the pointer of the current non-main co. The caller of this function must be a non-main co.
#define aco_get_co() ({(void)0; aco_gtls_co;})

// Same as aco_get_co().
#define aco_co() ({(void)0; aco_gtls_co;})

// Destroy the co. The argument co must not be NULL. The private save stack would also been
// destroyed if the co is a non-main co.
extern void aco_destroy(aco_t* co);

#define aco_is_main_co(co) ({((co)->main_co) == NULL;})

#define aco_exit1(co) do {     \
    (co)->is_end = 1;           \
    aco_assert((co)->share_stack->owner == (co)); \
    (co)->share_stack->owner = NULL; \
    (co)->share_stack->align_validsz = 0; \
    aco_yield1((co));            \
    aco_assert(0);                  \
} while(0)

// In addition do the same as aco_yield(), aco_exit() also set co->is_end to 1 thus to mark the co
// at the status of "end".
#define aco_exit() do {       \
    aco_exit1(aco_gtls_co); \
} while(0)

#ifdef __cplusplus
}
#endif

#endif
