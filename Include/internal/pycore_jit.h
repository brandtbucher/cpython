#ifndef Py_INTERNAL_JIT_H
#define Py_INTERNAL_JIT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#define STACK_CACHE_DECLARE PyObject *_0, PyObject *_1, PyObject *_2, PyObject *_3
#define STACK_CACHE_DEFINE  PyObject *_0 = NULL, *_1 = NULL, *_2 = NULL, *_3 = NULL
#define STACK_CACHE_NULLS   NULL, NULL, NULL, NULL
#define STACK_CACHE_USE     _0, _1, _2, _3

#ifdef _PyJIT_ACTIVE
#define CLOBBER_REGISTER(R)            \
    do {                               \
        __asm__ inline ("":"=r"((R))); \
    } while(0)

#else
#define CLOBBER_REGISTER(R) \
    do {                    \
        (R) = NULL;         \
    } while(0)
#endif  // _PyJIT_ACTIVE

#ifdef _Py_JIT

typedef _Py_CODEUNIT *(*jit_func)(_PyInterpreterFrame *frame, PyObject **stack_pointer, PyThreadState *tstate, STACK_CACHE_DECLARE);

int _PyJIT_Compile(_PyExecutorObject *executor, const _PyUOpInstruction *trace, size_t length);
void _PyJIT_Free(_PyExecutorObject *executor);

#endif  // _Py_JIT

#ifdef __cplusplus
}
#endif

#endif // !Py_INTERNAL_JIT_H
