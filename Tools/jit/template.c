#include "Python.h"

#include "pycore_call.h"
#include "pycore_ceval.h"
#include "pycore_dict.h"
#include "pycore_emscripten_signal.h"
#include "pycore_intrinsics.h"
#include "pycore_jit.h"
#include "pycore_long.h"
#include "pycore_opcode_metadata.h"
#include "pycore_opcode_utils.h"
#include "pycore_range.h"
#include "pycore_setobject.h"
#include "pycore_sliceobject.h"

#include "jit_macros.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate)
{
    // Locals that the instruction implementations expect to exist:
    PATCH_VALUE(_PyExecutorObject *, current_executor, _JIT_EXECUTOR);
    int oparg;
    int opcode = _JIT_OPCODE;
    _PyUOpInstruction *next_uop;
    // Other stuff we need handy:
    PATCH_VALUE(uint16_t, _oparg, _JIT_OPARG);
    PATCH_VALUE(uint64_t, _operand, _JIT_OPERAND);
    // PATCH_VALUE(uint32_t, _target, _JIT_TARGET);
    // The actual instruction definitions (only one will be used):
    if (opcode == _JUMP_TO_TOP) {
        CHECK_EVAL_BREAKER();
        PATCH_JUMP(_JIT_TOP);
    }
    switch (opcode) {
#include "executor_cases.c.h"
        default:
            Py_UNREACHABLE();
    }
    PATCH_JUMP(_JIT_CONTINUE);
    // Labels that the instruction implementations expect to exist:
deoptimize:
    // PATCH_JUMP(_JIT_DEOPTIMIZE);
    ;
    PATCH_VALUE(uint32_t, _target, _JIT_TARGET);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return _PyCode_CODE(_PyFrame_GetCode(frame)) + _target;
error_tier_two:
    // PATCH_JUMP(_JIT_POP_0_ERROR);
    STACK_SHRINK(0);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
pop_1_error_tier_two:
    // PATCH_JUMP(_JIT_POP_1_ERROR);
    STACK_SHRINK(1);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
pop_2_error_tier_two:
    // PATCH_JUMP(_JIT_POP_2_ERROR);
    STACK_SHRINK(2);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
pop_3_error_tier_two:
    // PATCH_JUMP(_JIT_POP_3_ERROR);
    STACK_SHRINK(3);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
pop_4_error_tier_two:
    // PATCH_JUMP(_JIT_POP_4_ERROR);
    STACK_SHRINK(4);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
unbound_local_error_tier_two:
    // PATCH_JUMP(_JIT_UNBOUND_LOCAL_ERROR);
    ;
    PyObject *name = PyTuple_GetItem(_PyFrame_GetCode(frame)->co_names, oparg);
    _PyEval_FormatExcCheckArg(tstate, PyExc_UnboundLocalError, UNBOUNDLOCAL_ERROR_MSG, name);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
}
