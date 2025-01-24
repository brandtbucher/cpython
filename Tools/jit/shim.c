#include "Python.h"

#include "pycore_ceval.h"
#include "pycore_frame.h"
#include "pycore_jit.h"

#include "jit.h"

_Py_CODEUNIT *
_JIT_ENTRY(_PyInterpreterFrame *frame, _PyStackRef *stack_pointer, PyThreadState *tstate)
{
    // Note that this is *not* a tail call:
    PyCodeObject *code = _PyFrame_GetCode(frame);
    Py_INCREF(code);  // XXX: LEAK
    jit_func_preserve_none jump = (jit_func_preserve_none)code->_jit_offsets[frame->instr_ptr - _PyCode_CODE(code)];
    return jump(frame, stack_pointer, tstate);
}
