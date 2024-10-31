#ifdef _Py_JIT

#include "Python.h"

#include "pycore_abstract.h"
#include "pycore_bitutils.h"
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

#include <elf.h>

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

static unsigned char *
jit_alloc(size_t size)
{
    assert(size);
    assert(size % get_page_size() == 0);
#ifdef MS_WINDOWS
    int flags = MEM_COMMIT | MEM_RESERVE;
    unsigned char *memory = VirtualAlloc(NULL, size, flags, PAGE_READWRITE);
    int failed = memory == NULL;
#else
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    unsigned char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
    int failed = memory == MAP_FAILED;
#endif
    if (failed) {
        jit_error("unable to allocate memory");
        return NULL;
    }
    return memory;
}

static int
jit_free(unsigned char *memory, size_t size)
{
    assert(size);
    assert(size % get_page_size() == 0);
#ifdef MS_WINDOWS
    int failed = !VirtualFree(memory, 0, MEM_RELEASE);
#else
    int failed = munmap(memory, size);
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

#define SYMBOL_MASK_WORDS 4

typedef uint32_t symbol_mask[SYMBOL_MASK_WORDS];

typedef struct {
    unsigned char *mem;
    symbol_mask mask;
    size_t size;
} trampoline_state;

typedef struct {
    trampoline_state trampolines;
    uintptr_t instruction_starts[UOP_MAX_TRACE_LENGTH];
} jit_state;

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

void patch_aarch64_trampoline(unsigned char *location, int ordinal, jit_state *state);

#include "jit_stencils.h"

#if defined(__aarch64__) || defined(_M_ARM64)
    #define TRAMPOLINE_SIZE 16
#else
    #define TRAMPOLINE_SIZE 0
#endif

// Generate and patch AArch64 trampolines. The symbols to jump to are stored
// in the jit_stencils.h in the symbols_map.
void
patch_aarch64_trampoline(unsigned char *location, int ordinal, jit_state *state)
{
    // Masking is done modulo 32 as the mask is stored as an array of uint32_t
    const uint32_t symbol_mask = 1 << (ordinal % 32);
    const uint32_t trampoline_mask = state->trampolines.mask[ordinal / 32];
    assert(symbol_mask & trampoline_mask);

    // Count the number of set bits in the trampoline mask lower than ordinal,
    // this gives the index into the array of trampolines.
    int index = _Py_popcount32(trampoline_mask & (symbol_mask - 1));
    for (int i = 0; i < ordinal / 32; i++) {
        index += _Py_popcount32(state->trampolines.mask[i]);
    }

    uint32_t *p = (uint32_t*)(state->trampolines.mem + index * TRAMPOLINE_SIZE);
    assert((size_t)(index + 1) * TRAMPOLINE_SIZE <= state->trampolines.size);

    uint64_t value = (uintptr_t)symbols_map[ordinal];

    /* Generate the trampoline
       0: 58000048      ldr     x8, 8
       4: d61f0100      br      x8
       8: 00000000      // The next two words contain the 64-bit address to jump to.
       c: 00000000
    */
    p[0] = 0x58000048;
    p[1] = 0xD61F0100;
    p[2] = value & 0xffffffff;
    p[3] = value >> 32;

    patch_aarch64_26r(location, (uintptr_t)p);
}

static void
combine_symbol_mask(const symbol_mask src, symbol_mask dest)
{
    // Calculate the union of the trampolines required by each StencilGroup
    for (size_t i = 0; i < SYMBOL_MASK_WORDS; i++) {
        dest[i] |= src[i];
    }
}

typedef enum
{
  JIT_NOACTION = 0,
  JIT_REGISTER_FN,
  JIT_UNREGISTER_FN
} jit_actions_t;

struct jit_code_entry
{
  struct jit_code_entry *next_entry;
  struct jit_code_entry *prev_entry;
  const char *symfile_addr;
  uint64_t symfile_size;
};

struct jit_descriptor
{
  uint32_t version;
  /* This type should be jit_actions_t, but we use uint32_t
     to be explicit about the bitwidth.  */
  uint32_t action_flag;
  struct jit_code_entry *relevant_entry;
  struct jit_code_entry *first_entry;
};

/* GDB puts a breakpoint in this function.  */
void __attribute__((noinline)) __jit_debug_register_code(void) { };

/* Make sure to specify the version statically, because the
   debugger may check the version before we can set it.  */
struct jit_descriptor __jit_debug_descriptor = { 1, 0, 0, 0 };

// https://github.com/JuliaLang/julia/issues/17856:
void (*volatile jit_debug_register_code)(void) = __jit_debug_register_code;

typedef struct buffer {
    uint8_t *bytes;
    size_t num_bytes;
    size_t max_bytes;
} Buffer;

Buffer buf_new(void);
Buffer buf_new_with_capacity(size_t num_bytes);
void buf_free(Buffer buf);
void buf_grow_to(Buffer *buf, size_t num_bytes);
void buf_grow_by(Buffer *buf, size_t num_bytes);
size_t buf_append(Buffer *buf, const void *bytes, size_t len);
size_t buf_append_byte(Buffer *buf, uint8_t value);
size_t buf_append_half(Buffer *buf, uint16_t value);
size_t buf_append_word(Buffer *buf, uint32_t value);
size_t buf_append_long(Buffer *buf, uint64_t value);
size_t buf_append_addr(Buffer *buf, uintptr_t value);
size_t buf_append_str(Buffer *buf, const char *str);
size_t buf_append_hex(Buffer *buf, const char *str);

Buffer buf_new(void)
{
    static Buffer result = { NULL, 0, 0 };
    return result;
}
Buffer buf_new_with_capacity(size_t num_bytes)
{
    Buffer result = buf_new();
    buf_grow_to(&result, num_bytes);
    return result;
}
void buf_free(Buffer buf)
{
    free(buf.bytes);
}
void buf_grow_to(Buffer *buf, size_t num_bytes)
{
    if (num_bytes <= buf->max_bytes) return;
    size_t max_bytes = 8;
    while (num_bytes > max_bytes) max_bytes *= 2;

    uint8_t *new_bytes = realloc(buf->bytes, max_bytes);
    if (!new_bytes) {
        fprintf(stderr, "Failed to allocate %zu bytes.\n", max_bytes);
        exit(EXIT_FAILURE);
    }
    buf->bytes = new_bytes;
    buf->max_bytes = max_bytes;
}
void buf_grow_by(Buffer *buf, size_t num_bytes)
{
    buf_grow_to(buf, buf->num_bytes + num_bytes);
}
size_t buf_append(Buffer *buf, const void *bytes, size_t len)
{
    buf_grow_by(buf, len);
    size_t off = buf->num_bytes;
    memcpy(&buf->bytes[buf->num_bytes], bytes, len);
    buf->num_bytes += len;
    return off;
}
size_t buf_append_byte(Buffer *buf, uint8_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_half(Buffer *buf, uint16_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_word(Buffer *buf, uint32_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_long(Buffer *buf, uint64_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_addr(Buffer *buf, uintptr_t value)
{
    return buf_append(buf, &value, sizeof(value));
}
size_t buf_append_str(Buffer *buf, const char *str)
{
    return buf_append(buf, str, strlen(str) + 1);
}
size_t buf_append_hex(Buffer *buf, const char *str)
{
    size_t off = buf->num_bytes;
    while (*str) {
        int hi = *str++;
        int lo = *str++;
        char hexval[3] = { hi, lo, 0 };
        if (!isxdigit(hi)) lo = hi;
        if (!isxdigit(lo)) {
            if (isgraph(lo)) {
                fprintf(stderr, "'%c' is not a valid hex digit.\n", lo);
            } else {
                fprintf(stderr, "'\\x%02x' is not a valid hex digit.\n", lo);
            }
            exit(EXIT_FAILURE);
        }
        buf_append_byte(buf, strtoul(hexval, NULL, 16));
    }
    return off;
}

#define ARRAYSIZE(...) (sizeof(__VA_ARGS__) / sizeof(*(__VA_ARGS__)))

static size_t buf_append_sym(Buffer *buf, Elf64_Sym sym)
{
    return buf_append(buf, &sym, sizeof(sym));
}

static Buffer buf_make_executable(Buffer buf)
{
    uint8_t *executable = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (executable == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap %zu bytes: %s\n", buf.num_bytes, strerror(errno));
        exit(EXIT_FAILURE);
    }
    memcpy(executable, buf.bytes, buf.num_bytes);
    if (mprotect(executable, 4096, PROT_READ | PROT_EXEC)) {
        fprintf(stderr, "Failed to mprotect(%p, %zu, PROT_READ | PROT_EXEC).\n", executable, buf.num_bytes);
        exit(EXIT_FAILURE);
    }

    buf_free(buf);

    Buffer result;
    result.bytes = executable;
    result.num_bytes = 4096;
    result.max_bytes = 0;
    return result;
}
static void buf_free_executable(Buffer buf)
{
    if (munmap(buf.bytes, buf.num_bytes) < 0) {
        fprintf(stderr, "Failed to munmap(%p, %zu)\n", buf.bytes, buf.num_bytes);
        exit(EXIT_FAILURE);
    }
}

enum {
    /* You can add more sections, like `.rodata` or debug sections */
    SECTION_NULL,
    SECTION_TEXT,
    SECTION_DATA,
    SECTION_SYMTAB,
    SECTION_STRTAB,
    SECTION_SHSTRTAB,
    SECTION_COUNT
};
typedef struct JitObject {
    /* The elf header. */
    Elf64_Ehdr ehdr;
    /* We don't need a program header.
     * A program header is used to prepare a program for execution,
     * but because we are JIT compiling, we prepare the program ourselves.
     */
    Elf64_Phdr phdr[0];
    /* The section headers that tell GDB about the memory we JIT compiled. */
    Elf64_Shdr shdr[SECTION_COUNT];
    /* NOTE: You could totally pre-calculate the sizes of these buffers,
     * and allocate the entire object up front.
     */
    Buffer symtab;
    Buffer strtab;
    Buffer shstrtab;
} JitObject;

/* Prepare a `JitObject` for adding symbols to. */
JitObject jit_begin(void)
{
    JitObject object;

    memset(&object, 0x00, sizeof(JitObject));
    object.ehdr.e_ident[EI_MAG0]       = ELFMAG0;
    object.ehdr.e_ident[EI_MAG1]       = ELFMAG1;
    object.ehdr.e_ident[EI_MAG2]       = ELFMAG2;
    object.ehdr.e_ident[EI_MAG3]       = ELFMAG3;
    object.ehdr.e_ident[EI_CLASS]      = ELFCLASS64;
    object.ehdr.e_ident[EI_DATA]       = ELFDATA2LSB;
    object.ehdr.e_ident[EI_VERSION]    = EV_CURRENT;
    object.ehdr.e_ident[EI_OSABI]      = ELFOSABI_NONE;
    object.ehdr.e_ident[EI_ABIVERSION] = 0;
    /* NOTE: `ET_EXEC` will work too, that makes GDB treat `.st_value`s as VMAs. */
    object.ehdr.e_type                 = ET_REL;
    object.ehdr.e_machine              = EM_X86_64;
    object.ehdr.e_version              = EV_CURRENT;
    /* NOTE: `.e_entry` is completely unused. */
    object.ehdr.e_entry                = 0x0;
    /* NOTE: `readelf` gives a warning if `.e_phoff` is non-zero, but `.e_phnum` is zero.
     * Setting this to `offsetof(...)` is otherwise harmless. */
    object.ehdr.e_phoff                = ARRAYSIZE(object.phdr) ? offsetof(JitObject, phdr) : 0;
    /* NOTE: `readelf` gives a warning if `.e_shoff` is non-zero, but `.e_shnum` is zero.
     * Setting this to `offsetof(...)` is otherwise harmless. */
    object.ehdr.e_shoff                = ARRAYSIZE(object.shdr) ? offsetof(JitObject, shdr) : 0;
    /* EM_X86_64 doesn't have machine flags. */
    object.ehdr.e_flags                = 0;
    object.ehdr.e_ehsize               = sizeof(Elf64_Ehdr);
    /* NOTE: `gcc` sets this to zero if `.e_phnum` is zero, so let's do the same. */
    object.ehdr.e_phentsize            = ARRAYSIZE(object.phdr) ? sizeof(Elf64_Phdr) : 0;
    object.ehdr.e_phnum                = ARRAYSIZE(object.phdr);
    /* NOTE: `gcc` sets this to zero if `.e_shnum` is zero, so let's do the same. */
    object.ehdr.e_shentsize            = ARRAYSIZE(object.shdr) ? sizeof(Elf64_Shdr) : 0;
    object.ehdr.e_shnum                = ARRAYSIZE(object.shdr);
    object.ehdr.e_shstrndx             = SECTION_SHSTRTAB;

    /* The NULL symbol, MUST exist as the first symbol. */
    buf_append_sym(&object.symtab, (Elf64_Sym){
        /* Can be any name. Most tools set this to 0 and place the empty string there. */
        .st_name  = buf_append_str(&object.strtab, ""),
        .st_value = 0,
        .st_size  = 0,
        .st_info  = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE), /* = 0 */
        .st_other = STV_DEFAULT, /* = 0 */
        .st_shndx = 0,
    });

    return object;
}
/* Finish adding symbols to a `JitObject`, and return the object as a continuous buffer. */
Buffer jit_complete(JitObject object, unsigned char *text, size_t text_size, unsigned char *data, size_t data_size)
{
    size_t header_sizes = sizeof(object.ehdr) + sizeof(object.phdr) + sizeof(object.shdr);
    size_t symtab_offset = header_sizes;
    size_t strtab_offset = symtab_offset + object.symtab.num_bytes;
    size_t shstrtab_offset = strtab_offset + object.strtab.num_bytes;

    /* SHT_NULL, MUST exist as the first section.
     * Can be any name. Most tools set this to 0 and place the empty string there. */
    object.shdr[SECTION_NULL].sh_name      = buf_append_str(&object.shstrtab, "");
    object.shdr[SECTION_NULL].sh_type      = SHT_NULL;
    object.shdr[SECTION_NULL].sh_flags     = 0;
    object.shdr[SECTION_NULL].sh_addr      = 0;
    object.shdr[SECTION_NULL].sh_offset    = 0;
    object.shdr[SECTION_NULL].sh_size      = 0;
    object.shdr[SECTION_NULL].sh_link      = 0;
    object.shdr[SECTION_NULL].sh_info      = 0;
    object.shdr[SECTION_NULL].sh_addralign = 0;
    object.shdr[SECTION_NULL].sh_entsize   = 0;
    /* .text */
    object.shdr[SECTION_TEXT].sh_name      = buf_append_str(&object.shstrtab, ".text");
    object.shdr[SECTION_TEXT].sh_type      = SHT_PROGBITS;
    object.shdr[SECTION_TEXT].sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
    object.shdr[SECTION_TEXT].sh_addr      = (uintptr_t)text;
    object.shdr[SECTION_TEXT].sh_offset    = 0;
    object.shdr[SECTION_TEXT].sh_size      = text_size;
    object.shdr[SECTION_TEXT].sh_link      = 0;
    object.shdr[SECTION_TEXT].sh_info      = 0;
    object.shdr[SECTION_TEXT].sh_addralign = 1 << 0;
    object.shdr[SECTION_TEXT].sh_entsize   = 0;
    /* .data */
    object.shdr[SECTION_DATA].sh_name      = buf_append_str(&object.shstrtab, ".data");
    object.shdr[SECTION_DATA].sh_type      = SHT_PROGBITS;
    object.shdr[SECTION_DATA].sh_flags     = SHF_ALLOC | SHF_WRITE;
    object.shdr[SECTION_DATA].sh_addr      = (uintptr_t)data;
    object.shdr[SECTION_DATA].sh_offset    = 0;
    object.shdr[SECTION_DATA].sh_size      = data_size;
    object.shdr[SECTION_DATA].sh_link      = 0;
    object.shdr[SECTION_DATA].sh_info      = 0;
    object.shdr[SECTION_DATA].sh_addralign = 1 << 0;
    object.shdr[SECTION_DATA].sh_entsize   = 0;
    /* .symtab */
    object.shdr[SECTION_SYMTAB].sh_name      = buf_append_str(&object.shstrtab, ".symtab");
    object.shdr[SECTION_SYMTAB].sh_type      = SHT_SYMTAB;
    object.shdr[SECTION_SYMTAB].sh_flags     = SHF_ALLOC;
    object.shdr[SECTION_SYMTAB].sh_addr      = (uintptr_t)object.symtab.bytes;
    object.shdr[SECTION_SYMTAB].sh_offset    = symtab_offset;
    object.shdr[SECTION_SYMTAB].sh_size      = object.symtab.num_bytes;
    /* NOTE: This can be any `SHT_STRTAB` section. You could re-use `.shstrtab` to save space. Most tools don't. */
    object.shdr[SECTION_SYMTAB].sh_link      = SECTION_STRTAB;
    object.shdr[SECTION_SYMTAB].sh_info      = (object.symtab.num_bytes / sizeof(Elf64_Sym));
    object.shdr[SECTION_SYMTAB].sh_addralign = 1 << 0;
    object.shdr[SECTION_SYMTAB].sh_entsize   = sizeof(Elf64_Sym);
    /* .strtab */
    object.shdr[SECTION_STRTAB].sh_name      = buf_append_str(&object.shstrtab, ".strtab");
    object.shdr[SECTION_STRTAB].sh_type      = SHT_STRTAB;
    object.shdr[SECTION_STRTAB].sh_flags     = SHF_ALLOC | SHF_STRINGS; /* NOTE: `SHF_STRINGS` is optional. */
    object.shdr[SECTION_STRTAB].sh_addr      = (uintptr_t)object.strtab.bytes;
    object.shdr[SECTION_STRTAB].sh_offset    = strtab_offset;
    object.shdr[SECTION_STRTAB].sh_size      = object.strtab.num_bytes;
    object.shdr[SECTION_STRTAB].sh_link      = 0;
    object.shdr[SECTION_STRTAB].sh_info      = 0;
    object.shdr[SECTION_STRTAB].sh_addralign = 1 << 0;
    /* Because we set `SHF_STRINGS`, this is "the size of each character". */
    object.shdr[SECTION_STRTAB].sh_entsize   = 1;
    /* .shstrtab */
    object.shdr[SECTION_SHSTRTAB].sh_name      = buf_append_str(&object.shstrtab, ".shstrtab");
    object.shdr[SECTION_SHSTRTAB].sh_type      = SHT_STRTAB;
    object.shdr[SECTION_SHSTRTAB].sh_flags     = SHF_ALLOC | SHF_STRINGS; /* NOTE: `SHF_STRINGS` is optional. */
    object.shdr[SECTION_SHSTRTAB].sh_addr      = (uintptr_t)object.shstrtab.bytes;
    object.shdr[SECTION_SHSTRTAB].sh_offset    = shstrtab_offset;
    object.shdr[SECTION_SHSTRTAB].sh_size      = object.shstrtab.num_bytes;
    object.shdr[SECTION_SHSTRTAB].sh_link      = 0;
    object.shdr[SECTION_SHSTRTAB].sh_info      = 0;
    object.shdr[SECTION_SHSTRTAB].sh_addralign = 1 << 0;
    /* Because we set `SHF_STRINGS`, this is "the size of each character". */
    object.shdr[SECTION_SHSTRTAB].sh_entsize   = 1;

    Buffer result = buf_new_with_capacity(
        header_sizes + object.symtab.num_bytes + object.strtab.num_bytes + object.shstrtab.num_bytes
    );

    buf_append(&result, &object.ehdr, sizeof(object.ehdr));
    buf_append(&result, &object.phdr, sizeof(object.phdr));
    buf_append(&result, &object.shdr, sizeof(object.shdr));
    buf_append(&result, object.symtab.bytes, object.symtab.num_bytes);
    buf_append(&result, object.strtab.bytes, object.strtab.num_bytes);
    buf_append(&result, object.shstrtab.bytes, object.shstrtab.num_bytes);

    buf_free(object.shstrtab);
    buf_free(object.strtab);
    buf_free(object.symtab);

    return result;
}

/*
 * You can break on this function to step into the JIT code,
 * and then print a backtrace to see if the symbols are working.
 */
void jit_run(void (*func)(void))
{
    func();
}

void *emit(char *name, unsigned char *memory, size_t code_size, size_t data_size)
{

    JitObject object = jit_begin();

    /* Add the symbols. */
    buf_append_sym(&object.symtab, (Elf64_Sym){
        .st_name = buf_append_str(&object.strtab, name),
        .st_value = 0, /* Offset into `.text` */
        .st_size = code_size, /* Size of the function. MUST be non-zero, or symbol will be unusable. */
        .st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC), /* A function. */
        .st_other = STV_DEFAULT,
        .st_shndx = SECTION_TEXT, /* The section index of this symbol (`.text`). */
    });
    buf_append_sym(&object.symtab, (Elf64_Sym){
        .st_name = buf_append_str(&object.strtab, "data"),
        .st_value = 0, /* Offset into `.data`` */
        .st_size = data_size, /* Size of the object. MUST be non-zero, or symbol will be unusable. */
        .st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT), /* An object. */
        .st_other = STV_DEFAULT,
        .st_shndx = SECTION_DATA, /* The section index of this symbol (`.data`). */
    });

    /* Create the object file in memory for GDB. */
    Buffer buf = jit_complete(object, memory, code_size, memory + code_size, data_size);

    // {
    //     /* Save the object file to disk.
    //      * Useful for checking the content with `readelf -a jit.o`
    //      * or `objdump -x jit.o` */
    //     FILE *fp = fopen("jit.o", "wb");
    //     if (!fp) {
    //         fprintf(stderr, "Failed to open \"jit.o\": %s\n", strerror(errno));
    //         exit(EXIT_FAILURE);
    //     }
    //     fwrite(buf.bytes, 1, buf.num_bytes, fp);
    //     fclose(fp);
    // }

    struct jit_code_entry *entry = malloc(sizeof(struct jit_code_entry));

    {
        /* Tell GDB about the object file we created. */
        /* https://sourceware.org/gdb/current/onlinedocs/gdb.html/Registering-Code.html */
        entry->prev_entry = NULL;
        entry->next_entry = __jit_debug_descriptor.first_entry;
        if (entry->next_entry) {
            entry->next_entry->prev_entry = entry;
        }
        entry->symfile_addr = (void*)buf.bytes;
        entry->symfile_size = buf.num_bytes;

        __jit_debug_descriptor.action_flag = JIT_REGISTER_FN;
        __jit_debug_descriptor.relevant_entry = entry;
        __jit_debug_descriptor.first_entry = entry;

        jit_debug_register_code();
    }

    return 0;
}

// Compiles executor in-place. Don't forget to call _PyJIT_Free later!
int
_PyJIT_Compile(_PyExecutorObject *executor, const _PyUOpInstruction trace[], size_t length, PyCodeObject *co)
{
    const StencilGroup *group;
    // Loop once to find the total compiled size:
    size_t code_size = 0;
    size_t data_size = 0;
    jit_state state = {0};
    group = &trampoline;
    code_size += group->code_size;
    data_size += group->data_size;
    combine_symbol_mask(group->trampoline_mask, state.trampolines.mask);
    for (size_t i = 0; i < length; i++) {
        const _PyUOpInstruction *instruction = &trace[i];
        group = &stencil_groups[instruction->opcode];
        state.instruction_starts[i] = code_size;
        code_size += group->code_size;
        data_size += group->data_size;
        combine_symbol_mask(group->trampoline_mask, state.trampolines.mask);
    }
    group = &stencil_groups[_FATAL_ERROR];
    code_size += group->code_size;
    data_size += group->data_size;
    combine_symbol_mask(group->trampoline_mask, state.trampolines.mask);
    // Calculate the size of the trampolines required by the whole trace
    for (size_t i = 0; i < Py_ARRAY_LENGTH(state.trampolines.mask); i++) {
        state.trampolines.size += _Py_popcount32(state.trampolines.mask[i]) * TRAMPOLINE_SIZE;
    }
    // Round up to the nearest page:
    size_t page_size = get_page_size();
    assert((page_size & (page_size - 1)) == 0);
    size_t padding = page_size - ((code_size + data_size + state.trampolines.size) & (page_size - 1));
    size_t total_size = code_size + data_size + state.trampolines.size + padding;
    unsigned char *memory = jit_alloc(total_size);
    if (memory == NULL) {
        return -1;
    }
    // Update the offsets of each instruction:
    for (size_t i = 0; i < length; i++) {
        state.instruction_starts[i] += (uintptr_t)memory;
    }
    // Loop again to emit the code:
    unsigned char *code = memory;
    unsigned char *data = memory + code_size;
    state.trampolines.mem = memory + code_size + data_size;
    // Compile the trampoline, which handles converting between the native
    // calling convention and the calling convention used by jitted code
    // (which may be different for efficiency reasons). On platforms where
    // we don't change calling conventions, the trampoline is empty and
    // nothing is emitted here:
    group = &trampoline;
    group->emit(code, data, executor, NULL, &state);
    code += group->code_size;
    data += group->data_size;
    assert(trace[0].opcode == _START_EXECUTOR);
    for (size_t i = 0; i < length; i++) {
        const _PyUOpInstruction *instruction = &trace[i];
        group = &stencil_groups[instruction->opcode];
        group->emit(code, data, executor, instruction, &state);
        code += group->code_size;
        data += group->data_size;
    }
    // Protect against accidental buffer overrun into data:
    group = &stencil_groups[_FATAL_ERROR];
    group->emit(code, data, executor, NULL, &state);
    code += group->code_size;
    data += group->data_size;
    assert(code == memory + code_size);
    assert(data == memory + code_size + data_size);
    if (mark_executable(memory, total_size)) {
        jit_free(memory, total_size);
        return -1;
    }
    executor->jit_code = memory;
    executor->jit_side_entry = memory + trampoline.code_size;
    executor->jit_size = total_size;
    char symbol[100];
    PyObject *bytes = PyUnicode_AsASCIIString(co->co_qualname);
    snprintf(symbol, sizeof(symbol), "[JIT: %s]", PyBytes_AS_STRING(bytes));
    Py_DECREF(bytes);
    emit("[JIT: <shim>]", memory, trampoline.code_size, 0);
    emit(symbol, memory + trampoline.code_size, code_size, data_size);

    return 0;
}

void
_PyJIT_Free(_PyExecutorObject *executor)
{
    unsigned char *memory = (unsigned char *)executor->jit_code;
    size_t size = executor->jit_size;
    if (memory) {
        executor->jit_code = NULL;
        executor->jit_side_entry = NULL;
        executor->jit_size = 0;
        if (jit_free(memory, size)) {
            PyErr_WriteUnraisable(NULL);
        }
    }
}

#endif  // _Py_JIT
