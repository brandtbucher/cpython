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

int _PyJIT_Compile(_PyExecutorObject *executor);
void _PyJIT_Free(_PyExecutorObject *executor);
int _PyJIT_Recompile(PyInterpreterState *interp);

#endif  // _Py_JIT

typedef struct {
    Py_ssize_t refs;
    Py_ssize_t test_refs;
    unsigned char *memory;
    size_t size;
} jit_allocation;

#ifdef __cplusplus
}
#endif

#endif // !Py_INTERNAL_JIT_H
