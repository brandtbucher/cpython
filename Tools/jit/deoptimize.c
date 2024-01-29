#include "Python.h"

#include "pycore_ceval.h"
#include "pycore_frame.h"

#include "jit_macros.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate)
{
    PATCH_VALUE(uint32_t, _target, _JIT_TARGET);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return _PyCode_CODE(_PyFrame_GetCode(frame)) + _target;
}
