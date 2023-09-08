typedef _PyInterpreterFrame *(*_PyJITFunction)(_PyExecutorObject *executor, _PyInterpreterFrame *frame, PyObject **stack_pointer);

PyAPI_FUNC(_PyJITFunction) _PyJIT_CompileTrace(_PyUOpInstruction *trace, int size, int stack_level);

#define MAX_STACK_LEVEL (6)

#define PACK_STACK                                          \
    PyObject *_0, PyObject *_1, PyObject *_2, PyObject *_3, \
    PyObject *_4, PyObject *_5

#define UNPACK_STACK                                                \
    _stack_base[0], _stack_base[1], _stack_base[2], _stack_base[3], \
    _stack_base[4], _stack_base[5]

#define BUILD_STACK \
    _0, _1, _2, _3, _4, _5
