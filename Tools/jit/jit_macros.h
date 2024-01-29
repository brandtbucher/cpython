#include "ceval_macros.h"

#undef CURRENT_OPARG
#define CURRENT_OPARG() (_oparg)

#undef CURRENT_OPERAND
#define CURRENT_OPERAND() (_operand)

#undef DEOPT_IF
#define DEOPT_IF(COND, INSTNAME) \
    do {                         \
        if ((COND)) {            \
            goto deoptimize;     \
        }                        \
    } while (0)

#undef ENABLE_SPECIALIZATION
#define ENABLE_SPECIALIZATION (0)

#undef GOTO_ERROR
#define GOTO_ERROR(LABEL)        \
    do {                         \
        goto LABEL ## _tier_two; \
    } while (0)

#undef LOAD_IP
#define LOAD_IP(UNUSED) \
    do {                \
    } while (0)

#define PATCH_VALUE(TYPE, NAME, ALIAS)  \
    extern void ALIAS;                  \
    TYPE NAME = (TYPE)(uint64_t)&ALIAS

#define PATCH_JUMP(ALIAS)                                        \
    do {                                                         \
        extern void ALIAS;                                       \
        __attribute__((musttail))                                \
        return ((jit_func)&ALIAS)(frame, stack_pointer, tstate); \
    } while (0)