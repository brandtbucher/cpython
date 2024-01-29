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
    PATCH_JUMP(_JIT_DEOPTIMIZE);
error_tier_two:
    PATCH_JUMP(_JIT_POP_0_ERROR);
pop_1_error_tier_two:
    PATCH_JUMP(_JIT_POP_1_ERROR);
pop_2_error_tier_two:
    PATCH_JUMP(_JIT_POP_2_ERROR);
pop_3_error_tier_two:
    PATCH_JUMP(_JIT_POP_3_ERROR);
pop_4_error_tier_two:
    PATCH_JUMP(_JIT_POP_4_ERROR);
unbound_local_error_tier_two:
    PATCH_JUMP(_JIT_UNBOUND_LOCAL_ERROR);
}
