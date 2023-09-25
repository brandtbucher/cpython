#include "Python.h"

#include "pycore_call.h"
#include "pycore_ceval.h"
#include "pycore_dict.h"
#include "pycore_emscripten_signal.h"
#include "pycore_intrinsics.h"
#include "pycore_long.h"
#include "pycore_object.h"
#include "pycore_opcode_metadata.h"
#include "pycore_opcode_utils.h"
#include "pycore_pyerrors.h"
#include "pycore_range.h"
#include "pycore_setobject.h"
#include "pycore_sliceobject.h"
#include "pycore_uops.h"
#include "pycore_jit.h"

#define TIER_TWO 2
#include "ceval_macros.h"

#include "opcode.h"

#undef DEOPT_IF
#define DEOPT_IF(COND, INSTNAME) \
    if ((COND)) {                \
        goto deoptimize;         \
    }
#undef ENABLE_SPECIALIZATION
#define ENABLE_SPECIALIZATION 0

// Stuff that will be patched at "JIT time":
extern _PyInterpreterFrame *_JIT_CONTINUE(_PyInterpreterFrame *frame,
                                          PyThreadState *tstate, PACK_STACK);
extern _PyInterpreterFrame *_JIT_DEOPT(_PyInterpreterFrame *frame,
                                       PyThreadState *tstate, PACK_STACK);
extern _PyInterpreterFrame *_JIT_JUMP(_PyInterpreterFrame *frame,
                                      PyThreadState *tstate, PACK_STACK);
// The address of an extern can't be 0:
extern void _JIT_OPARG_PLUS_ONE;
extern void _JIT_OPERAND_PLUS_ONE;

#undef STACK_LEVEL  // XXX
#define STACK_LEVEL() ((int)(stack_pointer - _stack_base))

#undef STORE_SP  // XXX
#define STORE_SP()                                                                                 \
    do {                                                                                           \
        _PyFrame_SetStackPointer(frame, _PyFrame_Stackbase(frame) + STACK_LEVEL());                \
        /* memmove(_PyFrame_Stackbase(frame), _stack_base, sizeof(PyObject *) * STACK_LEVEL()); */ \
        switch (STACK_LEVEL()) {                                                                   \
            case 10: _PyFrame_Stackbase(frame)[9] = _stack_base[9];                                \
            case 9: _PyFrame_Stackbase(frame)[8] = _stack_base[8];                                 \
            case 8: _PyFrame_Stackbase(frame)[7] = _stack_base[7];                                 \
            case 7: _PyFrame_Stackbase(frame)[6] = _stack_base[6];                                 \
            case 6: _PyFrame_Stackbase(frame)[5] = _stack_base[5];                                 \
            case 5: _PyFrame_Stackbase(frame)[4] = _stack_base[4];                                 \
            case 4: _PyFrame_Stackbase(frame)[3] = _stack_base[3];                                 \
            case 3: _PyFrame_Stackbase(frame)[2] = _stack_base[2];                                 \
            case 2: _PyFrame_Stackbase(frame)[1] = _stack_base[1];                                 \
            case 1: _PyFrame_Stackbase(frame)[0] = _stack_base[0];                                 \
            case 0: break; \
        } \
    } while (0)

#undef LOAD_SP  // XXX
#define LOAD_SP()                                                                                  \
    do {                                                                                           \
        stack_pointer = &_stack_base[_PyFrame_GetStackPointer(frame) - _PyFrame_Stackbase(frame)]; \
        /* memmove(_stack_base, _PyFrame_Stackbase(frame), sizeof(PyObject *) * STACK_LEVEL()); */ \
        switch (STACK_LEVEL()) {                                                                   \
            case 10: _stack_base[9] = _PyFrame_Stackbase(frame)[9];                                \
            case 9: _stack_base[8] = _PyFrame_Stackbase(frame)[8];                                 \
            case 8: _stack_base[7] = _PyFrame_Stackbase(frame)[7];                                 \
            case 7: _stack_base[6] = _PyFrame_Stackbase(frame)[6];                                 \
            case 6: _stack_base[5] = _PyFrame_Stackbase(frame)[5];                                 \
            case 5: _stack_base[4] = _PyFrame_Stackbase(frame)[4];                                 \
            case 4: _stack_base[3] = _PyFrame_Stackbase(frame)[3];                                 \
            case 3: _stack_base[2] = _PyFrame_Stackbase(frame)[2];                                 \
            case 2: _stack_base[1] = _PyFrame_Stackbase(frame)[1];                                 \
            case 1: _stack_base[0] = _PyFrame_Stackbase(frame)[0];                                 \
            case 0: break;                                                                         \
        }                                                                                          \
    } while (0)

_PyInterpreterFrame *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyThreadState *tstate, PACK_STACK)
{
    // Locals that the instruction implementations expect to exist:
    uint32_t opcode = _JIT_OPCODE;
    int32_t oparg = (uintptr_t)&_JIT_OPARG_PLUS_ONE - 1;
    uint64_t operand = (uintptr_t)&_JIT_OPERAND_PLUS_ONE - 1;
    int pc = -1;  // XXX
    PyObject *_stack_base[MAX_STACK_LEVEL];
    PyObject **stack_pointer = &_stack_base[_JIT_STACK_LEVEL];
    switch (STACK_LEVEL()) {
        case 10: _stack_base[9] = _9;
        case 9: _stack_base[8] = _8;
        case 8: _stack_base[7] = _7;
        case 7: _stack_base[6] = _6;
        case 6: _stack_base[5] = _5;
        case 5: _stack_base[4] = _4;
        case 4: _stack_base[3] = _3;
        case 3: _stack_base[2] = _2;
        case 2: _stack_base[1] = _1;
        case 1: _stack_base[0] = _0;
        case 0: break;
    }
    switch (opcode) {
        // Now, the actual instruction definitions (only one will be used):
#include "executor_cases.c.h"
        default:
            Py_UNREACHABLE();
    }
    // Finally, the continuations:
    if (pc != -1) {
        assert(pc == oparg);
        assert(opcode == _JUMP_TO_TOP ||
               opcode == _POP_JUMP_IF_FALSE ||
               opcode == _POP_JUMP_IF_TRUE);
        __attribute__((musttail))
        return _JIT_JUMP(frame, tstate, UNPACK_STACK);
    }
    __attribute__((musttail))
    return _JIT_CONTINUE(frame, tstate, UNPACK_STACK);
    // Labels that the instruction implementations expect to exist:
unbound_local_error:
    _PyEval_FormatExcCheckArg(tstate, PyExc_UnboundLocalError,
        UNBOUNDLOCAL_ERROR_MSG,
        PyTuple_GetItem(_PyFrame_GetCode(frame)->co_localsplusnames, oparg)
    );
    goto error;
pop_4_error:
    STACK_SHRINK(1);
pop_3_error:
    STACK_SHRINK(1);
pop_2_error:
    STACK_SHRINK(1);
pop_1_error:
    STACK_SHRINK(1);
error:
    STORE_SP();
    return NULL;
deoptimize:
    ;
    __attribute__((musttail))
    return _JIT_DEOPT(frame, tstate, UNPACK_STACK);
}
