#include "Python.h"

#include "pycore_frame.h"
#include "pycore_uops.h"
#include "pycore_jit.h"

// Stuff that will be patched at "JIT time":
extern _PyInterpreterFrame *_jit_continue(_PyInterpreterFrame *frame,
                                          PyThreadState *tstate, PACK_STACK);

_PyInterpreterFrame *
_jit_trampoline(_PyExecutorObject *executor, _PyInterpreterFrame *frame,
                PyObject **stack_pointer)
{
    PyThreadState *tstate = PyThreadState_Get();
    PyObject *_stack_base[MAX_STACK_LEVEL];
    memmove(_stack_base, _PyFrame_Stackbase(frame), sizeof(PyObject *) * (stack_pointer - _PyFrame_Stackbase(frame)));
    frame = _jit_continue(frame, tstate, UNPACK_STACK);
    Py_DECREF(executor);
    return frame;
}
