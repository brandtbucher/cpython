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

int _PyJIT_Compile(_PyExecutorObject *executor, const _PyUOpInstruction *trace, size_t length);
void _PyJIT_Free(_PyExecutorObject *executor);

#endif  // _Py_JIT

#define JIT_ALLOC_PAGES (1 << 10)

typedef struct jit_arena {
    struct jit_arena *prev;
    struct jit_arena *next;
    uint64_t used[JIT_ALLOC_PAGES];
    unsigned char *base;
} jit_arena;

typedef struct {
    jit_arena *arena;
} jit_state;

#ifdef __cplusplus
}
#endif

#endif // !Py_INTERNAL_JIT_H
