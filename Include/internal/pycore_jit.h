#ifndef Py_INTERNAL_JIT_H
#define Py_INTERNAL_JIT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#ifdef _Py_JIT

typedef _Py_CODEUNIT *(*jit_func)(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate);

#ifdef _PyJIT_FRAME_POINTER_HACK
typedef _Py_CODEUNIT *(*jit_func_frame_pointer_hack)(_PyInterpreterFrame *frame, void *frame_pointer_hack, PyObject **stack_pointer, PyThreadState *tstate);
#define JIT_CALL(FUNC, FRAME, FRAME_POINTER_HACK, STACK_POINTER, TSTATE) \
    (((jit_func_frame_pointer_hack)(FUNC))((FRAME), (FRAME_POINTER_HACK), (STACK_POINTER), (TSTATE)))
#else
#define JIT_CALL(FUNC, FRAME, FRAME_POINTER_HACK, STACK_POINTER, TSTATE) \
    (((jit_func)(FUNC))((FRAME), (STACK_POINTER), (TSTATE)))
#endif

int _PyJIT_Compile(_PyExecutorObject *executor, const _PyUOpInstruction *trace, size_t length);
void _PyJIT_Free(_PyExecutorObject *executor);

#endif  // _Py_JIT

#ifdef __cplusplus
}
#endif

#endif // !Py_INTERNAL_JIT_H
