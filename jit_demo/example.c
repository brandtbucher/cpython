/* I spent an entire evening getting JIT debug symbols to work in GDB.
 * Here is a minimal example to get you started.
 * Have fun!
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <elf.h>

#include "jit.h"

#define BUFFER_IMPLEMENTATION
#include "buffer.h"

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
Buffer jit_complete(JitObject object, Buffer text, Buffer data)
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
    object.shdr[SECTION_TEXT].sh_addr      = (uintptr_t)text.bytes;
    object.shdr[SECTION_TEXT].sh_offset    = 0;
    object.shdr[SECTION_TEXT].sh_size      = text.num_bytes;
    object.shdr[SECTION_TEXT].sh_link      = 0;
    object.shdr[SECTION_TEXT].sh_info      = 0;
    object.shdr[SECTION_TEXT].sh_addralign = 1 << 0;
    object.shdr[SECTION_TEXT].sh_entsize   = 0;
    /* .data */
    object.shdr[SECTION_DATA].sh_name      = buf_append_str(&object.shstrtab, ".data");
    object.shdr[SECTION_DATA].sh_type      = SHT_PROGBITS;
    object.shdr[SECTION_DATA].sh_flags     = SHF_ALLOC | SHF_WRITE;
    object.shdr[SECTION_DATA].sh_addr      = (uintptr_t)data.bytes;
    object.shdr[SECTION_DATA].sh_offset    = 0;
    object.shdr[SECTION_DATA].sh_size      = data.num_bytes;
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

void *yolo(char *name)
{
    Buffer data = buf_new();
    Buffer text = buf_new();

    /* Add some code to run... */
    buf_append_str(&data, "Hello, world!");

    buf_append_hex(&text, "48bf");      /* mov rdi, msg */
    buf_append_addr(&text, (uintptr_t)data.bytes);
    buf_append_hex(&text, "48b8");      /* mov rax, puts */
    buf_append_addr(&text, (uintptr_t)puts);
    buf_append_hex(&text, "ffd0");      /* call rax */

    buf_append_hex(&text, "31c0");      /* xor eax, eax */
    buf_append_hex(&text, "cc");        /* int3 */
    buf_append_hex(&text, "c3");        /* ret */

    text = buf_make_executable(text);
    text.num_bytes = 4096;
    data.num_bytes = 0;

    JitObject object = jit_begin();

    /* Add the symbols. */
    buf_append_sym(&object.symtab, (Elf64_Sym){
        .st_name = buf_append_str(&object.strtab, name),
        .st_value = 0, /* Offset into `.text` */
        .st_size = text.num_bytes, /* Size of the function. MUST be non-zero, or symbol will be unusable. */
        .st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC), /* A function. */
        .st_other = STV_DEFAULT,
        .st_shndx = SECTION_TEXT, /* The section index of this symbol (`.text`). */
    });
    buf_append_sym(&object.symtab, (Elf64_Sym){
        .st_name = buf_append_str(&object.strtab, "msg"),
        .st_value = 0, /* Offset into `.data`` */
        .st_size = data.num_bytes, /* Size of the object. MUST be non-zero, or symbol will be unusable. */
        .st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT), /* An object. */
        .st_other = STV_DEFAULT,
        .st_shndx = SECTION_DATA, /* The section index of this symbol (`.data`). */
    });

    /* Create the object file in memory for GDB. */
    Buffer buf = jit_complete(object, text, data);

    {
        /* Save the object file to disk.
         * Useful for checking the content with `readelf -a jit.o`
         * or `objdump -x jit.o` */
        FILE *fp = fopen("jit.o", "wb");
        if (!fp) {
            fprintf(stderr, "Failed to open \"jit.o\": %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        fwrite(buf.bytes, 1, buf.num_bytes, fp);
        fclose(fp);
    }

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

        __jit_debug_register_code();
        printf("XXX\n");
    }

    return text.bytes;
}

int main(void)
{
    void *x = yolo("jit_x");
    jit_run((void(*)(void))x);
    void *y = yolo("jit_y");
    jit_run((void(*)(void))x);
    jit_run((void(*)(void))y);
    void *z = yolo("jit_z");
    jit_run((void(*)(void))x);
    jit_run((void(*)(void))y);
    jit_run((void(*)(void))z);
    return 0;
}