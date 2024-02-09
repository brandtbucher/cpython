
#ifndef Py_LIMITED_API
#ifndef Py_OPTIMIZER_H
#define Py_OPTIMIZER_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct _PyExecutorLinkListNode {
    struct _PyExecutorObject *next;
    struct _PyExecutorObject *previous;
} _PyExecutorLinkListNode;


/* Bloom filter with m = 256
 * https://en.wikipedia.org/wiki/Bloom_filter */
#define BLOOM_FILTER_WORDS 8

typedef struct _bloom_filter {
    uint32_t bits[BLOOM_FILTER_WORDS];
} _PyBloomFilter;

typedef struct {
    uint8_t opcode;
    uint8_t oparg;
    uint8_t valid;
    uint8_t linked;
    int index;           // Index of ENTER_EXECUTOR (if code isn't NULL, below).
    _PyBloomFilter bloom;
    _PyExecutorLinkListNode links;
    PyCodeObject *code;  // Weak (NULL if no corresponding ENTER_EXECUTOR).
} _PyVMData;

typedef struct {
    uint16_t opcode;
    uint16_t oparg;
    union {
        uint32_t target;
        uint16_t exit_index;
    };
    uint64_t operand;  // A cache entry
} _PyUOpInstruction;

typedef struct _exit_data {
    uint32_t target;
    int16_t temperature;
    const struct _PyExecutorObject *executor;
} _PyExitData;

typedef struct _PyExecutorObject {
    PyObject_VAR_HEAD
    const _PyUOpInstruction *trace;
    _PyVMData vm_data; /* Used by the VM, but opaque to the optimizer */
    uint32_t exit_count;
    uint32_t code_size;
    void *jit_code;
    size_t jit_size;
    _PyExitData exits[1];
} _PyExecutorObject;

typedef struct _cold_exit {
    _PyExecutorObject base;
    _PyUOpInstruction uop;
} _PyColdExitObject;


typedef struct _PyOptimizerObject _PyOptimizerObject;

/* Should return > 0 if a new executor is created. O if no executor is produced and < 0 if an error occurred. */
typedef int (*optimize_func)(
    _PyOptimizerObject* self, struct _PyInterpreterFrame *frame,
    _Py_CODEUNIT *instr, _PyExecutorObject **exec_ptr,
    int curr_stackentries);

typedef struct _PyOptimizerObject {
    PyObject_HEAD
    optimize_func optimize;
    /* These thresholds are treated as signed so do not exceed INT16_MAX
     * Use INT16_MAX to indicate that the optimizer should never be called */
    uint16_t resume_threshold;
    uint16_t backedge_threshold;
    /* Data needed by the optimizer goes here, but is opaque to the VM */
} _PyOptimizerObject;

/** Test support **/
typedef struct {
    _PyOptimizerObject base;
    int64_t count;
} _PyCounterOptimizerObject;

PyAPI_FUNC(int) PyUnstable_Replace_Executor(PyCodeObject *code, _Py_CODEUNIT *instr, _PyExecutorObject *executor);

PyAPI_FUNC(void) PyUnstable_SetOptimizer(_PyOptimizerObject* optimizer);

PyAPI_FUNC(_PyOptimizerObject *) PyUnstable_GetOptimizer(void);

PyAPI_FUNC(_PyExecutorObject *) PyUnstable_GetExecutor(PyCodeObject *code, int offset);

int
_PyOptimizer_Optimize(struct _PyInterpreterFrame *frame, _Py_CODEUNIT *start, PyObject **stack_pointer, _PyExecutorObject **exec_ptr);

extern _PyOptimizerObject _PyOptimizer_Default;

void _Py_ExecutorInit(_PyExecutorObject *, const _PyBloomFilter *);
void _Py_ExecutorClear(_PyExecutorObject *);
void _Py_BloomFilter_Init(_PyBloomFilter *);
void _Py_BloomFilter_Add(_PyBloomFilter *bloom, void *obj);
PyAPI_FUNC(void) _Py_Executor_DependsOn(_PyExecutorObject *executor, void *obj);
PyAPI_FUNC(void) _Py_Executors_InvalidateDependency(PyInterpreterState *interp, void *obj);
extern void _Py_Executors_InvalidateAll(PyInterpreterState *interp);

/* For testing */
PyAPI_FUNC(PyObject *)PyUnstable_Optimizer_NewCounter(void);
PyAPI_FUNC(PyObject *)PyUnstable_Optimizer_NewUOpOptimizer(void);

#define OPTIMIZER_BITS_IN_COUNTER 4
/* Minimum of 16 additional executions before retry */
#define MINIMUM_TIER2_BACKOFF 4

#define _Py_MAX_ALLOWED_BUILTINS_MODIFICATIONS 3
#define _Py_MAX_ALLOWED_GLOBALS_MODIFICATIONS 6

#ifdef __cplusplus
}
#endif
#endif /* !Py_OPTIMIZER_H */
#endif /* Py_LIMITED_API */
