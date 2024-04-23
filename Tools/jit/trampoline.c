#include "Python.h"

#include "pycore_ceval.h"
#include "pycore_frame.h"
#include "pycore_jit.h"

_Py_CODEUNIT *
_ENTRY(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate)
{
    PyAPI_DATA(void) _JIT_EXECUTOR;
    PyObject *executor = (PyObject *)(uintptr_t)&_JIT_EXECUTOR;
    Py_INCREF(executor);
    PyAPI_DATA(void) _JIT_CONTINUE;
    void *_frame_pointer_hack = __builtin_frame_address(0);
    _Py_CODEUNIT *target = ((jit_func_ghccc)&_JIT_CONTINUE)(frame, _frame_pointer_hack, stack_pointer, tstate);
    Py_SETREF(tstate->previous_executor, executor);
    return target;
}
