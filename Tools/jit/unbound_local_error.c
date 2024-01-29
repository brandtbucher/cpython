#include "Python.h"

#include "pycore_ceval.h"
#include "pycore_frame.h"

#include "jit_macros.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate)
{
    PATCH_VALUE(uint16_t, _oparg, _JIT_OPARG);
    PyObject *name = PyTuple_GetItem(_PyFrame_GetCode(frame)->co_names, _oparg);
    _PyEval_FormatExcCheckArg(tstate, PyExc_UnboundLocalError, UNBOUNDLOCAL_ERROR_MSG, name);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
}
