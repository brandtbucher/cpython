#include "Python.h"

#include "pycore_frame.h"

// Stuff that will be patched at "JIT time":
extern _PyInterpreterFrame *_JIT_CONTINUE(PyThreadState *tstate,
                                          _PyInterpreterFrame *frame,
                                          PyObject **stack_pointer);

_PyInterpreterFrame *
_JIT_TRAMPOLINE(_PyExecutorObject *executor, _PyInterpreterFrame *frame,
                PyObject **stack_pointer)
{
    PyThreadState *tstate = PyThreadState_Get();
    frame = _JIT_CONTINUE(tstate, frame, stack_pointer);
    Py_DECREF(executor);
    return frame;
}
