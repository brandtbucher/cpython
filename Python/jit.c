#ifdef _Py_JIT

#include "Python.h"

#include "pycore_abstract.h"
#include "pycore_call.h"
#include "pycore_ceval.h"
#include "pycore_critical_section.h"
#include "pycore_dict.h"
#include "pycore_intrinsics.h"
#include "pycore_long.h"
#include "pycore_opcode_metadata.h"
#include "pycore_opcode_utils.h"
#include "pycore_optimizer.h"
#include "pycore_pyerrors.h"
#include "pycore_setobject.h"
#include "pycore_sliceobject.h"
#include "pycore_jit.h"

// Memory management stuff: ////////////////////////////////////////////////////

#ifndef MS_WINDOWS
    #include <sys/mman.h>
#endif

static size_t
get_page_size(void)
{
#ifdef MS_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return sysconf(_SC_PAGESIZE);
#endif
}

static void
jit_error(const char *message)
{
#ifdef MS_WINDOWS
    int hint = GetLastError();
#else
    int hint = errno;
#endif
    PyErr_Format(PyExc_RuntimeWarning, "JIT %s (%d)", message, hint);
}

size_t
jit_round_up(size_t size, size_t alignment)
{
    assert((alignment & (alignment - 1)) == 0);
    return size + alignment - (size & (alignment - 1));
}

static size_t allocated = 0;
static size_t wasted = 0;
static size_t ticks = 0;

static jit_arena *
jit_alloc_arena(void)
{
#ifdef MS_WINDOWS
    int flags = MEM_COMMIT | MEM_RESERVE;
    jit_arena *arena = VirtualAlloc(NULL, (JIT_ALLOC_PAGES + 2) * get_page_size(), flags, PAGE_READWRITE);
    int failed = arena == NULL;
#else
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    jit_arena *arena = mmap(NULL, (JIT_ALLOC_PAGES + 2) * get_page_size(), PROT_READ | PROT_WRITE, flags, -1, 0);
    int failed = arena == MAP_FAILED;
#endif
    if (failed) {
        jit_error("unable to allocate memory");
        return NULL;
    }
    for (size_t page = 0; page < Py_ARRAY_LENGTH(arena->used); page++) {
        arena->used[page] = 0;
    }
    arena->base = (unsigned char *)arena + (0 + 2) * get_page_size();
    return arena;
}

//  1 (16384): 3072: 83.330864%
//  2  (8192): 3072: 67.740036%
//  4  (4096): 3072: 47.461105%
//  8  (2048): 3072: 29.373699%
// 16  (1024): 3072: 15.429018%
// 32   (512): 3072: 9.898035%
// 64   (256): 3072: 4.842486%

#define CHUNKS_PER_PAGE (64)

static unsigned char *
jit_alloc_from_arena(size_t size, jit_arena *arena)
{
    assert(size);
    size_t chunk_size = get_page_size() / CHUNKS_PER_PAGE;
    size_t chunks_needed = jit_round_up(size, chunk_size) / chunk_size;
    // printf("XXX: %lu %lu\n", size, chunks_needed);
    size_t chunk_start = 0;
    for (size_t chunk = 0; chunk < Py_ARRAY_LENGTH(arena->used) * CHUNKS_PER_PAGE; chunk++) {
        // if ((arena->used[chunk / CHUNKS_PER_PAGE]) && (size == 0)) {  // XXX
        //     abort();
        // }
        if (arena->used[chunk / CHUNKS_PER_PAGE] & (1ULL << (chunk % CHUNKS_PER_PAGE))) {
            chunk_start = chunk + 1;
        }
        else if ((chunk + 1 - chunk_start) == chunks_needed) {
            for (size_t bit = 0; bit < chunks_needed; bit++) {
                arena->used[(chunk_start + bit) / CHUNKS_PER_PAGE] |= 1ULL << ((chunk_start + bit) % CHUNKS_PER_PAGE);
            }
            return arena->base + chunk_start * chunk_size;
        }
    }
    return NULL;
}

static int
jit_alloc(size_t size, jit_arena **arena, unsigned char **memory)
{
    assert(size);
    allocated += size;
    wasted += jit_round_up(size, get_page_size() / CHUNKS_PER_PAGE) - size;
    if (++ticks % (1 << 10) == 0) {
        printf("XXX: %lu: %f%%\n", ticks, (float)wasted / (allocated + wasted) * 100);
    }
    jit_state *jit = &_PyInterpreterState_GET()->jit;
    *arena = jit->arena;
    while (*arena) {
        *memory = jit_alloc_from_arena(size, *arena);
        if (*memory) {
            return 0;
        }
        *arena = (*arena)->next;
    }
    jit_arena *new_arena = jit_alloc_arena();
    if (new_arena == NULL) {
        return -1;
    }
    new_arena->prev = NULL;
    new_arena->next = jit->arena;
    if (jit->arena) {
        jit->arena->prev = new_arena;
    }
    jit->arena = new_arena;
    *arena = jit->arena;
    *memory = jit_alloc_from_arena(size, *arena);
    assert(*memory);
    return 0;
}

static int
jit_free(size_t size, jit_arena *arena, unsigned char *memory)
{
    assert(size);
    allocated -= size;
    wasted -= jit_round_up(size, get_page_size() / CHUNKS_PER_PAGE) - size;
    // printf("Wasted: %f%%\n", (float)wasted / (allocated + wasted) * 100);
    size_t chunk_size = get_page_size() / CHUNKS_PER_PAGE;
    size_t chunks_needed = jit_round_up(size, chunk_size) / chunk_size;
    assert((memory - arena->base) % chunk_size == 0);
    size_t chunk_start = (memory - arena->base) / chunk_size;
    for (size_t bit = 0; bit < chunks_needed; bit++) {
        assert(arena->used[(chunk_start + bit) / CHUNKS_PER_PAGE] & (1ULL << ((chunk_start + bit) % CHUNKS_PER_PAGE)));
        arena->used[(chunk_start + bit) / CHUNKS_PER_PAGE] &= ~(1ULL << ((chunk_start + bit) % CHUNKS_PER_PAGE));
    }
    for (size_t page = 0; page < Py_ARRAY_LENGTH(arena->used); page++) {
        if (arena->used[page]) {
            return 0;
        }
    }
    jit_state *jit = &_PyInterpreterState_GET()->jit;
    if (arena->prev) {
        arena->prev->next = arena->next;
    }
    else {
        jit->arena = arena->next;
    }
    if (arena->next) {
        arena->next->prev = arena->prev;
    }
#ifdef MS_WINDOWS
    int failed = !VirtualFree(arena, 0, MEM_RELEASE);
#else
    int failed = munmap(arena, (JIT_ALLOC_PAGES + 2) * get_page_size());
#endif
    if (failed) {
        jit_error("unable to free memory");
        return -1;
    }
    return 0;
}

static int
mark_executable(unsigned char *memory, size_t size)
{
    assert(size);
    size_t page_size = get_page_size();
    unsigned char *base = (unsigned char *)((uintptr_t)memory & ~(page_size - 1));
    size = jit_round_up(size + memory - base, page_size);
    // Do NOT ever leave the memory writable! Also, don't forget to flush the
    // i-cache (I cannot begin to tell you how horrible that is to debug):
#ifdef MS_WINDOWS
    if (!FlushInstructionCache(GetCurrentProcess(), base, size)) {
        jit_error("unable to flush instruction cache");
        return -1;
    }
    int old;
    int failed = !VirtualProtect(base, size, PAGE_EXECUTE_READ, &old);
#else
    __builtin___clear_cache((char *)base, (char *)base + size);
    int failed = mprotect(base, size, PROT_EXEC | PROT_READ);
#endif
    if (failed) {
        jit_error("unable to protect executable memory");
        return -1;
    }
    return 0;
}

static int
mark_writeable(unsigned char *memory, size_t size)
{
    assert(size);
    size_t page_size = get_page_size();
    unsigned char *base = (unsigned char *)((uintptr_t)memory & ~(page_size - 1));
    size = jit_round_up(size + memory - base, page_size);
#ifdef MS_WINDOWS
    int old;
    int failed = !VirtualProtect(base, size, PAGE_READWRITE, &old);
#else
    int failed = mprotect(base, size, PROT_READ | PROT_WRITE);
#endif
    if (failed) {
        jit_error("unable to protect writeable memory");
        return -1;
    }
    return 0;
}

// JIT compiler stuff: /////////////////////////////////////////////////////////

// Warning! AArch64 requires you to get your hands dirty. These are your gloves:

// value[value_start : value_start + len]
static uint32_t
get_bits(uint64_t value, uint8_t value_start, uint8_t width)
{
    assert(width <= 32);
    return (value >> value_start) & ((1ULL << width) - 1);
}

// *loc[loc_start : loc_start + width] = value[value_start : value_start + width]
static void
set_bits(uint32_t *loc, uint8_t loc_start, uint64_t value, uint8_t value_start,
         uint8_t width)
{
    assert(loc_start + width <= 32);
    // Clear the bits we're about to patch:
    *loc &= ~(((1ULL << width) - 1) << loc_start);
    assert(get_bits(*loc, loc_start, width) == 0);
    // Patch the bits:
    *loc |= get_bits(value, value_start, width) << loc_start;
    assert(get_bits(*loc, loc_start, width) == get_bits(value, value_start, width));
}

// See https://developer.arm.com/documentation/ddi0602/2023-09/Base-Instructions
// for instruction encodings:
#define IS_AARCH64_ADD_OR_SUB(I) (((I) & 0x11C00000) == 0x11000000)
#define IS_AARCH64_ADRP(I)       (((I) & 0x9F000000) == 0x90000000)
#define IS_AARCH64_BRANCH(I)     (((I) & 0x7C000000) == 0x14000000)
#define IS_AARCH64_LDR_OR_STR(I) (((I) & 0x3B000000) == 0x39000000)
#define IS_AARCH64_MOV(I)        (((I) & 0x9F800000) == 0x92800000)

// LLD is a great reference for performing relocations... just keep in
// mind that Tools/jit/build.py does filtering and preprocessing for us!
// Here's a good place to start for each platform:
// - aarch64-apple-darwin:
//   - https://github.com/llvm/llvm-project/blob/main/lld/MachO/Arch/ARM64.cpp
//   - https://github.com/llvm/llvm-project/blob/main/lld/MachO/Arch/ARM64Common.cpp
//   - https://github.com/llvm/llvm-project/blob/main/lld/MachO/Arch/ARM64Common.h
// - aarch64-pc-windows-msvc:
//   - https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp
// - aarch64-unknown-linux-gnu:
//   - https://github.com/llvm/llvm-project/blob/main/lld/ELF/Arch/AArch64.cpp
// - i686-pc-windows-msvc:
//   - https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp
// - x86_64-apple-darwin:
//   - https://github.com/llvm/llvm-project/blob/main/lld/MachO/Arch/X86_64.cpp
// - x86_64-pc-windows-msvc:
//   - https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp
// - x86_64-unknown-linux-gnu:
//   - https://github.com/llvm/llvm-project/blob/main/lld/ELF/Arch/X86_64.cpp

// Many of these patches are "relaxing", meaning that they can rewrite the
// code they're patching to be more efficient (like turning a 64-bit memory
// load into a 32-bit immediate load). These patches have an "x" in their name.
// Relative patches have an "r" in their name.

// 32-bit absolute address.
void
patch_32(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    // Check that we're not out of range of 32 unsigned bits:
    assert(value < (1ULL << 32));
    *loc32 = (uint32_t)value;
}

// 32-bit relative address.
void
patch_32r(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    value -= (uintptr_t)location;
    // Check that we're not out of range of 32 signed bits:
    assert((int64_t)value >= -(1LL << 31));
    assert((int64_t)value < (1LL << 31));
    *loc32 = (uint32_t)value;
}

// 64-bit absolute address.
void
patch_64(unsigned char *location, uint64_t value)
{
    uint64_t *loc64 = (uint64_t *)location;
    *loc64 = value;
}

// 12-bit low part of an absolute address. Pairs nicely with patch_aarch64_21r
// (below).
void
patch_aarch64_12(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_LDR_OR_STR(*loc32) || IS_AARCH64_ADD_OR_SUB(*loc32));
    // There might be an implicit shift encoded in the instruction:
    uint8_t shift = 0;
    if (IS_AARCH64_LDR_OR_STR(*loc32)) {
        shift = (uint8_t)get_bits(*loc32, 30, 2);
        // If both of these are set, the shift is supposed to be 4.
        // That's pretty weird, and it's never actually been observed...
        assert(get_bits(*loc32, 23, 1) == 0 || get_bits(*loc32, 26, 1) == 0);
    }
    value = get_bits(value, 0, 12);
    assert(get_bits(value, 0, shift) == 0);
    set_bits(loc32, 10, value, shift, 12);
}

// Relaxable 12-bit low part of an absolute address. Pairs nicely with
// patch_aarch64_21rx (below).
void
patch_aarch64_12x(unsigned char *location, uint64_t value)
{
    // This can *only* be relaxed if it occurs immediately before a matching
    // patch_aarch64_21rx. If that happens, the JIT build step will replace both
    // calls with a single call to patch_aarch64_33rx. Otherwise, we end up
    // here, and the instruction is patched normally:
    patch_aarch64_12(location, value);
}

// 16-bit low part of an absolute address.
void
patch_aarch64_16a(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_MOV(*loc32));
    // Check the implicit shift (this is "part 0 of 3"):
    assert(get_bits(*loc32, 21, 2) == 0);
    set_bits(loc32, 5, value, 0, 16);
}

// 16-bit middle-low part of an absolute address.
void
patch_aarch64_16b(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_MOV(*loc32));
    // Check the implicit shift (this is "part 1 of 3"):
    assert(get_bits(*loc32, 21, 2) == 1);
    set_bits(loc32, 5, value, 16, 16);
}

// 16-bit middle-high part of an absolute address.
void
patch_aarch64_16c(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_MOV(*loc32));
    // Check the implicit shift (this is "part 2 of 3"):
    assert(get_bits(*loc32, 21, 2) == 2);
    set_bits(loc32, 5, value, 32, 16);
}

// 16-bit high part of an absolute address.
void
patch_aarch64_16d(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_MOV(*loc32));
    // Check the implicit shift (this is "part 3 of 3"):
    assert(get_bits(*loc32, 21, 2) == 3);
    set_bits(loc32, 5, value, 48, 16);
}

// 21-bit count of pages between this page and an absolute address's page... I
// know, I know, it's weird. Pairs nicely with patch_aarch64_12 (above).
void
patch_aarch64_21r(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    value = (value >> 12) - ((uintptr_t)location >> 12);
    // Check that we're not out of range of 21 signed bits:
    assert((int64_t)value >= -(1 << 20));
    assert((int64_t)value < (1 << 20));
    // value[0:2] goes in loc[29:31]:
    set_bits(loc32, 29, value, 0, 2);
    // value[2:21] goes in loc[5:26]:
    set_bits(loc32, 5, value, 2, 19);
}

// Relaxable 21-bit count of pages between this page and an absolute address's
// page. Pairs nicely with patch_aarch64_12x (above).
void
patch_aarch64_21rx(unsigned char *location, uint64_t value)
{
    // This can *only* be relaxed if it occurs immediately before a matching
    // patch_aarch64_12x. If that happens, the JIT build step will replace both
    // calls with a single call to patch_aarch64_33rx. Otherwise, we end up
    // here, and the instruction is patched normally:
    patch_aarch64_21r(location, value);
}

// 28-bit relative branch.
void
patch_aarch64_26r(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    assert(IS_AARCH64_BRANCH(*loc32));
    value -= (uintptr_t)location;
    // Check that we're not out of range of 28 signed bits:
    assert((int64_t)value >= -(1 << 27));
    assert((int64_t)value < (1 << 27));
    // Since instructions are 4-byte aligned, only use 26 bits:
    assert(get_bits(value, 0, 2) == 0);
    set_bits(loc32, 0, value, 2, 26);
}

// A pair of patch_aarch64_21rx and patch_aarch64_12x.
void
patch_aarch64_33rx(unsigned char *location, uint64_t value)
{
    uint32_t *loc32 = (uint32_t *)location;
    // Try to relax the pair of GOT loads into an immediate value:
    assert(IS_AARCH64_ADRP(*loc32));
    unsigned char reg = get_bits(loc32[0], 0, 5);
    assert(IS_AARCH64_LDR_OR_STR(loc32[1]));
    // There should be only one register involved:
    assert(reg == get_bits(loc32[1], 0, 5));  // ldr's output register.
    assert(reg == get_bits(loc32[1], 5, 5));  // ldr's input register.
    uint64_t relaxed = *(uint64_t *)value;
    if (relaxed < (1UL << 16)) {
        // adrp reg, AAA; ldr reg, [reg + BBB] -> movz reg, XXX; nop
        loc32[0] = 0xD2800000 | (get_bits(relaxed, 0, 16) << 5) | reg;
        loc32[1] = 0xD503201F;
        return;
    }
    if (relaxed < (1ULL << 32)) {
        // adrp reg, AAA; ldr reg, [reg + BBB] -> movz reg, XXX; movk reg, YYY
        loc32[0] = 0xD2800000 | (get_bits(relaxed,  0, 16) << 5) | reg;
        loc32[1] = 0xF2A00000 | (get_bits(relaxed, 16, 16) << 5) | reg;
        return;
    }
    relaxed = value - (uintptr_t)location;
    if ((relaxed & 0x3) == 0 &&
        (int64_t)relaxed >= -(1L << 19) &&
        (int64_t)relaxed < (1L << 19))
    {
        // adrp reg, AAA; ldr reg, [reg + BBB] -> ldr reg, XXX; nop
        loc32[0] = 0x58000000 | (get_bits(relaxed, 2, 19) << 5) | reg;
        loc32[1] = 0xD503201F;
        return;
    }
    // Couldn't do it. Just patch the two instructions normally:
    patch_aarch64_21rx(location, value);
    patch_aarch64_12x(location + 4, value);
}

// Relaxable 32-bit relative address.
void
patch_x86_64_32rx(unsigned char *location, uint64_t value)
{
    uint8_t *loc8 = (uint8_t *)location;
    // Try to relax the GOT load into an immediate value:
    uint64_t relaxed = *(uint64_t *)(value + 4) - 4;
    if ((int64_t)relaxed - (int64_t)location >= -(1LL << 31) &&
        (int64_t)relaxed - (int64_t)location + 1 < (1LL << 31))
    {
        if (loc8[-2] == 0x8B) {
            // mov reg, dword ptr [rip + AAA] -> lea reg, [rip + XXX]
            loc8[-2] = 0x8D;
            value = relaxed;
        }
        else if (loc8[-2] == 0xFF && loc8[-1] == 0x15) {
            // call qword ptr [rip + AAA] -> nop; call XXX
            loc8[-2] = 0x90;
            loc8[-1] = 0xE8;
            value = relaxed;
        }
        else if (loc8[-2] == 0xFF && loc8[-1] == 0x25) {
            // jmp qword ptr [rip + AAA] -> nop; jmp XXX
            loc8[-2] = 0x90;
            loc8[-1] = 0xE9;
            value = relaxed;
        }
    }
    patch_32r(location, value);
}

#include "jit_stencils.h"

// Compiles executor in-place. Don't forget to call _PyJIT_Free later!
int
_PyJIT_Compile(_PyExecutorObject *executor, const _PyUOpInstruction trace[], size_t length)
{
    const StencilGroup *group;
    // Loop once to find the total compiled size:
    uintptr_t instruction_starts[UOP_MAX_TRACE_LENGTH];
    size_t code_size = 0;
    size_t data_size = 0;
    group = &trampoline;
    code_size += group->code_size;
    data_size += group->data_size;
    for (size_t i = 0; i < length; i++) {
        const _PyUOpInstruction *instruction = &trace[i];
        group = &stencil_groups[instruction->opcode];
        instruction_starts[i] = code_size;
        code_size += group->code_size;
        data_size += group->data_size;
    }
    group = &stencil_groups[_FATAL_ERROR];
    code_size += group->code_size;
    data_size += group->data_size;
    size_t total_size = code_size + data_size;
    PyInterpreterState *interp = _PyInterpreterState_GET();
    _PyEval_StopTheWorld(interp);
    jit_arena *arena;
    unsigned char *memory;
    if (jit_alloc(total_size, &arena, &memory)) {
        goto failure;
    }
    if (mark_writeable(memory, total_size)) {
        jit_free(total_size, arena, memory);
        goto failure;
    }
    // Update the offsets of each instruction:
    for (size_t i = 0; i < length; i++) {
        instruction_starts[i] += (uintptr_t)memory;
    }
    // Loop again to emit the code:
    unsigned char *code = memory;
    unsigned char *data = memory + code_size;
    // Compile the trampoline, which handles converting between the native
    // calling convention and the calling convention used by jitted code
    // (which may be different for efficiency reasons). On platforms where
    // we don't change calling conventions, the trampoline is empty and
    // nothing is emitted here:
    group = &trampoline;
    group->emit(code, data, executor, NULL, instruction_starts);
    code += group->code_size;
    data += group->data_size;
    assert(trace[0].opcode == _START_EXECUTOR || trace[0].opcode == _COLD_EXIT);
    for (size_t i = 0; i < length; i++) {
        const _PyUOpInstruction *instruction = &trace[i];
        group = &stencil_groups[instruction->opcode];
        group->emit(code, data, executor, instruction, instruction_starts);
        code += group->code_size;
        data += group->data_size;
    }
    // Protect against accidental buffer overrun into data:
    group = &stencil_groups[_FATAL_ERROR];
    group->emit(code, data, executor, NULL, instruction_starts);
    code += group->code_size;
    data += group->data_size;
    assert(code == memory + code_size);
    assert(data == memory + code_size + data_size);
    if (mark_executable(memory, total_size)) {
        jit_free(total_size, arena, memory);
        goto failure;
    }
    executor->jit_arena = arena;
    executor->jit_code = memory;
    executor->jit_side_entry = memory + trampoline.code_size;
    executor->jit_size = total_size;
    _PyEval_StartTheWorld(interp);
    return 0;
failure:
    _PyEval_StartTheWorld(interp);
    return -1;
}

void
_PyJIT_Free(_PyExecutorObject *executor)
{
    size_t size = executor->jit_size;
    jit_arena *arena = executor->jit_arena;
    unsigned char *memory = (unsigned char *)executor->jit_code;
    if (memory) {
        executor->jit_arena = NULL;
        executor->jit_code = NULL;
        executor->jit_side_entry = NULL;
        executor->jit_size = 0;
        PyInterpreterState *interp = _PyInterpreterState_GET();
        _PyEval_StopTheWorld(interp);
        if (jit_free(size, arena, memory)) {
            PyErr_WriteUnraisable(NULL);
        }
        _PyEval_StartTheWorld(interp);
    }
}

#endif  // _Py_JIT
