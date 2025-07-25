#include "Python.h"

#include "pycore_ceval.h"
#include "pycore_frame.h"
#include "pycore_jit.h"

#include "jit.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyExecutorObject *executor, _PyInterpreterFrame *frame, _PyStackRef *stack_pointer, PyThreadState *tstate)
{
    // Note that this is *not* a tail call:
    return ((jit_func_preserve_none)executor->jit_code)(frame, stack_pointer, tstate);
}
