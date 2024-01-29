#include "Python.h"

#include "pycore_frame.h"

#include "jit_macros.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate)
{
    STACK_SHRINK(_JIT_STACK_SHRINK);
    _PyFrame_SetStackPointer(frame, stack_pointer);
    return NULL;
}
