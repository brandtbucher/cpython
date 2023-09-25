#include "Python.h"

#include "pycore_frame.h"
#include "pycore_uops.h"
#include "pycore_jit.h"

_PyInterpreterFrame *
_JIT_ENTRY(_PyInterpreterFrame *frame, PyThreadState *tstate, PACK_STACK)
{
    frame->prev_instr--;
    _PyFrame_SetStackPointer(frame, _PyFrame_Stackbase(frame) + _JIT_STACK_LEVEL);
    switch (_JIT_STACK_LEVEL) {
        case 10: _PyFrame_Stackbase(frame)[9] = _9;
        case 9: _PyFrame_Stackbase(frame)[8] = _8;
        case 8: _PyFrame_Stackbase(frame)[7] = _7;
        case 7: _PyFrame_Stackbase(frame)[6] = _6;
        case 6: _PyFrame_Stackbase(frame)[5] = _5;
        case 5: _PyFrame_Stackbase(frame)[4] = _4;
        case 4: _PyFrame_Stackbase(frame)[3] = _3;
        case 3: _PyFrame_Stackbase(frame)[2] = _2;
        case 2: _PyFrame_Stackbase(frame)[1] = _1;
        case 1: _PyFrame_Stackbase(frame)[0] = _0;
        case 0: break;
    }
    return frame;
}
