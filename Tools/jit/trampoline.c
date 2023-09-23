#include "Python.h"

#include "pycore_frame.h"
#include "pycore_uops.h"
#include "pycore_jit.h"

// Stuff that will be patched at "JIT time":
extern _PyInterpreterFrame *_JIT_CONTINUE(_PyInterpreterFrame *frame,
                                          PyThreadState *tstate, PACK_STACK);

_PyInterpreterFrame *
_JIT_TRAMPOLINE(_PyExecutorObject *executor, _PyInterpreterFrame *frame,
                PyObject **stack_pointer)
{
    PyThreadState *tstate = PyThreadState_Get();
    PyObject *_stack_base[MAX_STACK_LEVEL];
    // memmove(_stack_base, _PyFrame_Stackbase(frame), sizeof(PyObject *) * (stack_pointer - _PyFrame_Stackbase(frame)));
    switch (stack_pointer - _PyFrame_Stackbase(frame)) {
        case 10: _stack_base[9] = _PyFrame_Stackbase(frame)[9];
        case 9: _stack_base[8] = _PyFrame_Stackbase(frame)[8];
        case 8: _stack_base[7] = _PyFrame_Stackbase(frame)[7];
        case 7: _stack_base[6] = _PyFrame_Stackbase(frame)[6];
        case 6: _stack_base[5] = _PyFrame_Stackbase(frame)[5];
        case 5: _stack_base[4] = _PyFrame_Stackbase(frame)[4];
        case 4: _stack_base[3] = _PyFrame_Stackbase(frame)[3];
        case 3: _stack_base[2] = _PyFrame_Stackbase(frame)[2];
        case 2: _stack_base[1] = _PyFrame_Stackbase(frame)[1];
        case 1: _stack_base[0] = _PyFrame_Stackbase(frame)[0];
        case 0: break;
    }
    frame = _JIT_CONTINUE(frame, tstate, UNPACK_STACK);
    Py_DECREF(executor);
    return frame;
}
