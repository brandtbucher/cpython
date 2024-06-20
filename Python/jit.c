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

static size_t
round_up_to_page(size_t size)
{
    size_t page_size = get_page_size();
    assert((page_size & (page_size - 1)) == 0);
    size_t padding = page_size - (size & (page_size - 1));
    return size + padding;
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

static jit_allocation *
jit_alloc(size_t size)
{
    size_t total_size = round_up_to_page(size);
    assert(total_size);
    assert(total_size % get_page_size() == 0);
#ifdef MS_WINDOWS
    int flags = MEM_COMMIT | MEM_RESERVE;
    unsigned char *memory = VirtualAlloc(NULL, total_size, flags, PAGE_READWRITE);
    int failed = memory == NULL;
#else
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    unsigned char *memory = mmap(NULL, total_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    int failed = memory == MAP_FAILED;
#endif
    if (failed) {
        jit_error("unable to allocate memory");
        return NULL;
    }
    jit_allocation *allocation = PyMem_Malloc(sizeof(jit_allocation));
    if (allocation == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    allocation->refs = 1;
    allocation->memory = memory;
    allocation->size = size;
    return allocation;
}

static void
jit_free(jit_allocation *allocation)
{
    if (_Py_atomic_add_ssize(&allocation->refs, -1) != 1) {
        return;
    }
    size_t size = round_up_to_page(allocation->size);
    assert(size);
    assert(size % get_page_size() == 0);
#ifdef MS_WINDOWS
    int failed = !VirtualFree(allocation->memory, 0, MEM_RELEASE);
#else
    int failed = munmap(allocation->memory, size);
#endif
    if (failed) {
        jit_error("unable to free memory");
        PyErr_WriteUnraisable(NULL);
    }
    PyMem_Free(allocation);
}

static int
mark_executable(unsigned char *memory, size_t size)
{
    size = round_up_to_page(size);
    if (size == 0) {
        return 0;
    }
    assert(size % get_page_size() == 0);
    // Do NOT ever leave the memory writable! Also, don't forget to flush the
    // i-cache (I cannot begin to tell you how horrible that is to debug):
#ifdef MS_WINDOWS
    if (!FlushInstructionCache(GetCurrentProcess(), memory, size)) {
        jit_error("unable to flush instruction cache");
        return -1;
    }
    int old;
    int failed = !VirtualProtect(memory, size, PAGE_EXECUTE_READ, &old);
#else
    __builtin___clear_cache((char *)memory, (char *)memory + size);
    int failed = mprotect(memory, size, PROT_EXEC | PROT_READ);
#endif
    if (failed) {
        jit_error("unable to protect executable memory");
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

static size_t
compute_size(_PyExecutorObject *executor)
{
    const _PyUOpInstruction *trace = executor->trace;
    size_t length = executor->code_size;
    const StencilGroup *group;
    size_t size = 0;
    group = &trampoline;
    size += group->code_size + group->data_size;
    for (size_t i = 0; i < length; i++) {
        group = &stencil_groups[trace[i].opcode];
        size += group->code_size + group->data_size;
    }
    group = &stencil_groups[_FATAL_ERROR];
    size += group->code_size + group->data_size;
    return size;
}

static void
compile(_PyExecutorObject *executor, unsigned char *memory)
{
    const _PyUOpInstruction *trace = executor->trace;
    size_t length = executor->code_size;
    const StencilGroup *group;
    // Loop once to find the total compiled size:
    uintptr_t instruction_starts[UOP_MAX_TRACE_LENGTH];
    uintptr_t offset = 0;
    group = &trampoline;
    offset += group->code_size;
    for (size_t i = 0; i < length; i++) {
        const _PyUOpInstruction *instruction = &trace[i];
        group = &stencil_groups[instruction->opcode];
        instruction_starts[i] = (uintptr_t)memory + offset;
        offset += group->code_size;
    }
    group = &stencil_groups[_FATAL_ERROR];
    offset += group->code_size;
    unsigned char *code = memory;
    unsigned char *data = memory + offset;
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
}

typedef size_t (*callback_t)(_PyExecutorObject *, jit_allocation *, size_t);

static size_t
call_for_each_idle_executor(PyInterpreterState *interp, callback_t callback,
                            jit_allocation *allocation)
{
    size_t accumulator = 0;
    for (_PyExecutorObject *executor = interp->executor_list_head;
         executor != NULL; executor = executor->vm_data.links.next)
    {
        if (Py_REFCNT(executor) == 1 && executor->vm_data.code) {
            accumulator = callback(executor, allocation, accumulator);
        }
    }
    return accumulator;
}

static size_t
setref(_PyExecutorObject *executor, jit_allocation *Py_UNUSED(allocation),
       size_t Py_UNUSED(accumulator))
{
    jit_allocation *this_allocation = (jit_allocation *)executor->jit_allocation;
    this_allocation->test_refs = this_allocation->refs;
    return 0;
}

static size_t
decref(_PyExecutorObject *executor, jit_allocation *Py_UNUSED(allocation),
       size_t accumulator)
{
    jit_allocation *this_allocation = (jit_allocation *)executor->jit_allocation;
    if (--this_allocation->test_refs == 0) {
        accumulator += round_up_to_page(this_allocation->size);
    }
    return accumulator;
}

static size_t
resize(_PyExecutorObject *executor, jit_allocation *Py_UNUSED(allocation),
       size_t accumulator)
{
    jit_allocation *this_allocation = (jit_allocation *)executor->jit_allocation;
    if (this_allocation->test_refs == 0) {
        accumulator += executor->jit_size;
    }
    return accumulator;
}

static size_t
recompile(_PyExecutorObject *executor, jit_allocation *allocation,
       size_t accumulator)
{
    jit_allocation *this_allocation = (jit_allocation *)executor->jit_allocation;
    if (this_allocation->test_refs == 0) {
        compile(executor, allocation->memory + accumulator);
        accumulator += executor->jit_size;
    }
    return accumulator;
}

static size_t
fixup(_PyExecutorObject *executor, jit_allocation *allocation,
      size_t accumulator)
{
    jit_allocation *this_allocation = (jit_allocation *)executor->jit_allocation;
    if (this_allocation->test_refs == 0) {
        jit_free(this_allocation);
        allocation->refs += 1;
        executor->jit_allocation = allocation;
        executor->jit_code = allocation->memory + accumulator;
        executor->jit_side_entry = allocation->memory + accumulator + trampoline.code_size;
        accumulator += executor->jit_size;
    }
    return accumulator;
}

int
_PyJIT_Recompile(PyInterpreterState *interp)
{
    if (interp->jit_recompile == 0) {
        return 0;
    }
    interp->jit_recompile = 0;
    call_for_each_idle_executor(interp, setref, NULL);
    size_t freed_size = call_for_each_idle_executor(interp, decref, NULL);
    size_t size = call_for_each_idle_executor(interp, resize, NULL);
    if (size == 0 || freed_size <= round_up_to_page(size)) {
        return 0;
    }
    jit_allocation *allocation = jit_alloc(size);
    if (allocation == NULL) {
        return -1;
    }
    call_for_each_idle_executor(interp, recompile, allocation);
    if (mark_executable(allocation->memory, allocation->size)) {
        jit_free(allocation);
        return -1;
    }
    call_for_each_idle_executor(interp, fixup, allocation);
    assert(1 < allocation->refs);
    allocation->refs -= 1;
    return 0;
}

// Compiles executor in-place. Don't forget to call _PyJIT_Free later!
int
_PyJIT_Compile(_PyExecutorObject *executor)
{
    size_t size = compute_size(executor);
    jit_allocation *allocation = jit_alloc(size);
    if (allocation == NULL) {
        return -1;
    }
    compile(executor, allocation->memory);
    if (mark_executable(allocation->memory, allocation->size)) {
        jit_free(allocation);
        return -1;
    }
    executor->jit_allocation = allocation;
    executor->jit_code = allocation->memory;
    executor->jit_side_entry = allocation->memory + trampoline.code_size;
    executor->jit_size = size;
    _Py_atomic_store_uint8(&_PyInterpreterState_GET()->jit_recompile, 1);
    return 0;
}

void
_PyJIT_Free(_PyExecutorObject *executor)
{
    if (executor->jit_allocation) {
        jit_free((jit_allocation *)executor->jit_allocation);
        executor->jit_allocation = NULL;
    }
    executor->jit_code = NULL;
    executor->jit_side_entry = NULL;
    executor->jit_size = 0;
    _Py_atomic_store_uint8(&_PyInterpreterState_GET()->jit_recompile, 1);
}

#endif  // _Py_JIT
