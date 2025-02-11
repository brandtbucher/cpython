#include "Python.h"

#ifdef _Py_TIER2

#include "opcode.h"
#include "pycore_interp.h"
#include "pycore_backoff.h"
#include "pycore_bitutils.h"        // _Py_popcount32()
#include "pycore_object.h"          // _PyObject_GC_UNTRACK()
#include "pycore_opcode_metadata.h" // _PyOpcode_OpName[]
#include "pycore_opcode_utils.h"  // MAX_REAL_OPCODE
#include "pycore_optimizer.h"     // _Py_uop_analyze_and_optimize()
#include "pycore_pystate.h"       // _PyInterpreterState_GET()
#include "pycore_uop_ids.h"
#include "pycore_jit.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define NEED_OPCODE_METADATA
#include "pycore_uop_metadata.h" // Uop tables
#undef NEED_OPCODE_METADATA

#define MAX_EXECUTORS_SIZE 256

static bool
has_space_for_executor(PyCodeObject *code, _Py_CODEUNIT *instr)
{
    if (instr->op.code == ENTER_EXECUTOR) {
        return true;
    }
    if (code->co_executors == NULL) {
        return true;
    }
    return code->co_executors->size < MAX_EXECUTORS_SIZE;
}

static int32_t
get_index_for_executor(PyCodeObject *code, _Py_CODEUNIT *instr)
{
    if (instr->op.code == ENTER_EXECUTOR) {
        return instr->op.arg;
    }
    _PyExecutorArray *old = code->co_executors;
    int size = 0;
    int capacity = 0;
    if (old != NULL) {
        size = old->size;
        capacity = old->capacity;
        assert(size < MAX_EXECUTORS_SIZE);
    }
    assert(size <= capacity);
    if (size == capacity) {
        /* Array is full. Grow array */
        int new_capacity = capacity ? capacity * 2 : 4;
        _PyExecutorArray *new = PyMem_Realloc(
            old,
            offsetof(_PyExecutorArray, executors) +
            new_capacity * sizeof(_PyExecutorObject *));
        if (new == NULL) {
            return -1;
        }
        new->capacity = new_capacity;
        new->size = size;
        code->co_executors = new;
    }
    assert(size < code->co_executors->capacity);
    return size;
}

static void
insert_executor(PyCodeObject *code, _Py_CODEUNIT *instr, int index, _PyExecutorObject *executor)
{
    Py_INCREF(executor);
    if (instr->op.code == ENTER_EXECUTOR) {
        assert(index == instr->op.arg);
        _Py_ExecutorDetach(code->co_executors->executors[index]);
    }
    else {
        assert(code->co_executors->size == index);
        assert(code->co_executors->capacity > index);
        code->co_executors->size++;
    }
    executor->vm_data.opcode = instr->op.code;
    executor->vm_data.oparg = instr->op.arg;
    executor->vm_data.code = code;
    executor->vm_data.index = (int)(instr - _PyCode_CODE(code));
    code->co_executors->executors[index] = executor;
    assert(index < MAX_EXECUTORS_SIZE);
    instr->op.code = ENTER_EXECUTOR;
    instr->op.arg = index;
}

static _PyExecutorObject *
make_executor_from_uops(_PyUOpInstruction *buffer, int length, const _PyBloomFilter *dependencies);

static int
uop_optimize(_PyInterpreterFrame *frame, _Py_CODEUNIT *instr,
             _PyExecutorObject **exec_ptr, int curr_stackentries);

/* Returns 1 if optimized, 0 if not optimized, and -1 for an error.
 * If optimized, *executor_ptr contains a new reference to the executor
 */
int
_PyOptimizer_Optimize(
    _PyInterpreterFrame *frame, _Py_CODEUNIT *start,
    _PyExecutorObject **executor_ptr, int chain_depth)
{
    _PyStackRef *stack_pointer = frame->stackpointer;
    assert(_PyInterpreterState_GET()->jit);
    // The first executor in a chain and the MAX_CHAIN_DEPTH'th executor *must*
    // make progress in order to avoid infinite loops or excessively-long
    // side-exit chains. We can only insert the executor into the bytecode if
    // this is true, since a deopt won't infinitely re-enter the executor:
    chain_depth %= MAX_CHAIN_DEPTH;
    PyCodeObject *code = _PyFrame_GetCode(frame);
    assert(PyCode_Check(code));
    if (!has_space_for_executor(code, start)) {
        return 0;
    }
    int err = uop_optimize(frame, start, executor_ptr, (int)(stack_pointer - _PyFrame_Stackbase(frame)));
    if (err <= 0) {
        return err;
    }
    assert(*executor_ptr != NULL);
    int index = get_index_for_executor(code, start);
    if (index < 0) {
        /* Out of memory. Don't raise and assume that the
            * error will show up elsewhere.
            *
            * If an optimizer has already produced an executor,
            * it might get confused by the executor disappearing,
            * but there is not much we can do about that here. */
        (*executor_ptr)->vm_data.code = NULL;  // XXX
        Py_DECREF(*executor_ptr);
        return 0;
    }
    insert_executor(code, start, index, *executor_ptr);
    // This is initialized to true so we can prevent the executor
    // from being immediately detected as cold and invalidated.
    (*executor_ptr)->vm_data.warm = true;
    (*executor_ptr)->jit_code = NULL;
    (*executor_ptr)->jit_side_entry = NULL;
    (*executor_ptr)->jit_size = 0;
    (*executor_ptr)->vm_data.code = code;  // XXX
    uintptr_t last_seen = UINTPTR_MAX;
    for (int i = 0; i < Py_SIZE(code); i++) {
        uintptr_t offset = (*executor_ptr)->jit_offsets[i];
        if (offset != UINTPTR_MAX) {
            last_seen = offset;
        }
        (*executor_ptr)->jit_offsets[i] = last_seen;
    }
#ifdef _Py_JIT
    if (_PyJIT_Compile(*executor_ptr, (*executor_ptr)->trace, (*executor_ptr)->code_size)) {
        (*executor_ptr)->vm_data.code = NULL;  // XXX
        Py_DECREF(*executor_ptr);
        return -1;
    }
#endif
    (*executor_ptr)->vm_data.chain_depth = chain_depth;
    assert((*executor_ptr)->vm_data.valid);
    return 1;
}

static _PyExecutorObject *
get_executor_lock_held(PyCodeObject *code, int offset)
{
    int code_len = (int)Py_SIZE(code);
    for (int i = 0 ; i < code_len;) {
        if (_PyCode_CODE(code)[i].op.code == ENTER_EXECUTOR && i*2 == offset) {
            int oparg = _PyCode_CODE(code)[i].op.arg;
            _PyExecutorObject *res = code->co_executors->executors[oparg];
            Py_INCREF(res);
            return res;
        }
        i += _PyInstruction_GetLength(code, i);
    }
    PyErr_SetString(PyExc_ValueError, "no executor at given byte offset");
    return NULL;
}

_PyExecutorObject *
_Py_GetExecutor(PyCodeObject *code, int offset)
{
    _PyExecutorObject *executor;
    Py_BEGIN_CRITICAL_SECTION(code);
    executor = get_executor_lock_held(code, offset);
    Py_END_CRITICAL_SECTION();
    return executor;
}

static PyObject *
is_valid(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyBool_FromLong(((_PyExecutorObject *)self)->vm_data.valid);
}

static PyObject *
get_opcode(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromUnsignedLong(((_PyExecutorObject *)self)->vm_data.opcode);
}

static PyObject *
get_oparg(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromUnsignedLong(((_PyExecutorObject *)self)->vm_data.oparg);
}

///////////////////// Experimental UOp Optimizer /////////////////////

static int executor_clear(_PyExecutorObject *executor);
static void unlink_executor(_PyExecutorObject *executor);

static void
uop_dealloc(_PyExecutorObject *self) {
    _PyObject_GC_UNTRACK(self);
    assert(self->vm_data.code == NULL);
    unlink_executor(self);
    PyMem_Free(self->jit_offsets);
#ifdef _Py_JIT
    _PyJIT_Free(self);
#endif
    PyObject_GC_Del(self);
}

const char *
_PyUOpName(int index)
{
    if (index < 0 || index > MAX_UOP_ID) {
        return NULL;
    }
    return _PyOpcode_uop_name[index];
}

#ifdef Py_DEBUG
void
_PyUOpPrint(const _PyUOpInstruction *uop)
{
    const char *name = _PyUOpName(uop->opcode);
    if (name == NULL) {
        printf("<uop %d>", uop->opcode);
    }
    else {
        printf("%s", name);
    }
    switch(uop->format) {
        case UOP_FORMAT_TARGET:
            printf(" (%d, target=%d, operand=%#" PRIx64,
                uop->oparg,
                uop->target,
                (uint64_t)uop->operand0);
            break;
        case UOP_FORMAT_JUMP:
            printf(" (%d, jump_target=%d, operand=%#" PRIx64,
                uop->oparg,
                uop->jump_target,
                (uint64_t)uop->operand0);
            break;
        default:
            printf(" (%d, Unknown format)", uop->oparg);
    }
    if (_PyUop_Flags[uop->opcode] & HAS_ERROR_FLAG) {
        printf(", error_target=%d", uop->error_target);
    }

    printf(")");
}
#endif

static Py_ssize_t
uop_len(_PyExecutorObject *self)
{
    return self->code_size;
}

static PyObject *
uop_item(_PyExecutorObject *self, Py_ssize_t index)
{
    Py_ssize_t len = uop_len(self);
    if (index < 0 || index >= len) {
        PyErr_SetNone(PyExc_IndexError);
        return NULL;
    }
    const char *name = _PyUOpName(self->trace[index].opcode);
    if (name == NULL) {
        name = "<nil>";
    }
    PyObject *oname = _PyUnicode_FromASCII(name, strlen(name));
    if (oname == NULL) {
        return NULL;
    }
    PyObject *oparg = PyLong_FromUnsignedLong(self->trace[index].oparg);
    if (oparg == NULL) {
        Py_DECREF(oname);
        return NULL;
    }
    PyObject *target = PyLong_FromUnsignedLong(self->trace[index].target);
    if (oparg == NULL) {
        Py_DECREF(oparg);
        Py_DECREF(oname);
        return NULL;
    }
    PyObject *operand = PyLong_FromUnsignedLongLong(self->trace[index].operand0);
    if (operand == NULL) {
        Py_DECREF(target);
        Py_DECREF(oparg);
        Py_DECREF(oname);
        return NULL;
    }
    PyObject *args[4] = { oname, oparg, target, operand };
    return _PyTuple_FromArraySteal(args, 4);
}

PySequenceMethods uop_as_sequence = {
    .sq_length = (lenfunc)uop_len,
    .sq_item = (ssizeargfunc)uop_item,
};

static int
executor_traverse(PyObject *o, visitproc visit, void *arg)
{
    _PyExecutorObject *executor = (_PyExecutorObject *)o;
    for (uint32_t i = 0; i < executor->exit_count; i++) {
        Py_VISIT(executor->exits[i].executor);
    }
    return 0;
}

static PyObject *
get_jit_code(PyObject *self, PyObject *Py_UNUSED(ignored))
{
#ifndef _Py_JIT
    PyErr_SetString(PyExc_RuntimeError, "JIT support not enabled.");
    return NULL;
#else
    _PyExecutorObject *executor = (_PyExecutorObject *)self;
    if (executor->jit_code == NULL || executor->jit_size == 0) {
        Py_RETURN_NONE;
    }
    return PyBytes_FromStringAndSize(executor->jit_code, executor->jit_size);
#endif
}

static PyMethodDef uop_executor_methods[] = {
    { "is_valid", is_valid, METH_NOARGS, NULL },
    { "get_jit_code", get_jit_code, METH_NOARGS, NULL},
    { "get_opcode", get_opcode, METH_NOARGS, NULL },
    { "get_oparg", get_oparg, METH_NOARGS, NULL },
    { NULL, NULL },
};

static int
executor_is_gc(PyObject *o)
{
    return !_Py_IsImmortal(o);
}

PyTypeObject _PyUOpExecutor_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    .tp_name = "uop_executor",
    .tp_basicsize = offsetof(_PyExecutorObject, exits),
    .tp_itemsize = 1,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_HAVE_GC,
    .tp_dealloc = (destructor)uop_dealloc,
    .tp_as_sequence = &uop_as_sequence,
    .tp_methods = uop_executor_methods,
    .tp_traverse = executor_traverse,
    .tp_clear = (inquiry)executor_clear,
    .tp_is_gc = executor_is_gc,
};

#ifdef Py_DEBUG
void _PyUOpPrint(const _PyUOpInstruction *);
#endif

static const uint16_t
_PyUOp_Replacements[MAX_UOP_ID + 1] = {
    [_FOR_ITER] = _FOR_ITER_TIER_TWO,
    [_ITER_JUMP_LIST] = _GUARD_NOT_EXHAUSTED_LIST,
    [_ITER_JUMP_RANGE] = _GUARD_NOT_EXHAUSTED_RANGE,
    [_ITER_JUMP_TUPLE] = _GUARD_NOT_EXHAUSTED_TUPLE,
    [_POP_JUMP_IF_FALSE] = _GUARD_IS_TRUE_POP,
    // [_POP_JUMP_IF_NONE] = _GUARD_IS_NOT_NONE_POP,
    // [_POP_JUMP_IF_NOT_NONE] = _GUARD_IS_NONE_POP,
    [_POP_JUMP_IF_TRUE] = _GUARD_IS_FALSE_POP,
};

#define MAYBE_RESIZE()                                                     \
do {                                                                       \
    if (i2 == j2) {                                                        \
        j2 *= 2;                                                           \
        void *_new = PyMem_Realloc(trace, sizeof(_PyUOpInstruction) * j2); \
        if (_new == NULL) {                                                \
            goto error;                                                    \
        }                                                                  \
        trace = _new;                                                      \
    }                                                                      \
    assert(i2 < j2);                                                       \
} while (0)

#define ADD_UOP_TARGET(OPCODE, OPARG, OPERAND, TARGET) \
do {                                                   \
    MAYBE_RESIZE();                                    \
    _PyUOpInstruction *_uop = &trace[i2++];            \
    _uop->opcode = (OPCODE);                           \
    _uop->oparg = (OPARG);                             \
    _uop->operand0 = (OPERAND);                        \
    _uop->format = UOP_FORMAT_TARGET;                  \
    _uop->target = (TARGET);                           \
} while (0)

#define ADD_UOP_JUMP(OPCODE, OPARG, OPERAND, JUMP, ERROR) \
do {                                                      \
    MAYBE_RESIZE();                                       \
    _PyUOpInstruction *_uop = &trace[i2++];               \
    _uop->opcode = (OPCODE);                              \
    _uop->oparg = (OPARG);                                \
    _uop->operand0 = (OPERAND);                           \
    _uop->format = UOP_FORMAT_JUMP;                       \
    _uop->jump_target = (JUMP);                           \
    _uop->error_target = (ERROR);                         \
} while (0)

#define SIZE(OPCODE) (1 + _PyOpcode_Caches[_PyOpcode_Deopt[(OPCODE)]])

static int
translate_bytecode_to_trace(
    _PyInterpreterFrame *frame,
    _Py_CODEUNIT *instr,
    _PyUOpInstruction **trace_p,
    uintptr_t **offsets_p,
    _PyBloomFilter *dependencies)
{
    PyCodeObject *code = _PyFrame_GetCode(frame);
    assert(_PyInterpreterState_GET()->jit);
    _Py_CODEUNIT *instructions = _PyCode_CODE(code);
    size_t j1 = Py_SIZE(code);
    uintptr_t *offsets = PyMem_Malloc(sizeof(uintptr_t) * j1);
    if (offsets == NULL) {
        return -1;
    }
    memset(offsets, -1, sizeof(uintptr_t) * j1);
    size_t j2 = 1 << 8;  // XXX
    _PyUOpInstruction *trace = PyMem_Malloc(sizeof(_PyUOpInstruction) * j2);
    if (trace == NULL) {
        goto error;
    }
    size_t i1 = 0;
    size_t i2 = 0;
    ADD_UOP_TARGET(_START_EXECUTOR, 0, 0, 0);
    while (i1 < j1) {
        size_t start = i1;
        offsets[i1] = i2;
        uint8_t opcode = instructions[i1].op.code;
        uint16_t oparg = instructions[i1].op.arg;
        if (opcode == EXTENDED_ARG) {
            opcode = instructions[++i1].op.code;
            oparg = (oparg << 8) | instructions[i1].op.arg;
            if (opcode == EXTENDED_ARG) {
                ADD_UOP_TARGET(_DEOPT, 0, 0, start);
                while (opcode == EXTENDED_ARG) {
                    opcode = instructions[++i1].op.code;
                }
                goto loop;
            }
        }
        if (!OPCODE_HAS_NO_SAVE_IP(opcode)) {
            ADD_UOP_TARGET(_CHECK_VALIDITY_AND_SET_IP, 0, (uintptr_t)&instructions[i1], start);
        }
        switch (opcode) {
            case JUMP_BACKWARD_JIT:
            case JUMP_BACKWARD_NO_JIT:
            case JUMP_BACKWARD:
                ADD_UOP_TARGET(_CHECK_PERIODIC, 0, 0, start);
                ADD_UOP_TARGET(_MAKE_WARM, 0, 0, start);
                ADD_UOP_JUMP(_JUMP_TO_TOP, 0, 0, i1 + SIZE(opcode) - oparg, start);
                break;
            case JUMP_BACKWARD_NO_INTERRUPT:
                ADD_UOP_TARGET(_MAKE_WARM, 0, 0, start);
                ADD_UOP_JUMP(_JUMP_TO_TOP, 0, 0, i1 + SIZE(opcode) - oparg, start);
                break;
            case JUMP_FORWARD:
                ADD_UOP_JUMP(_JUMP_TO_TOP, 0, 0, i1 + SIZE(opcode) + oparg, start);
                break;
            default:
                ;
                const struct opcode_macro_expansion *expansion = &_PyOpcode_macro_expansion[opcode];
                if (expansion->nuops) {
                    uint32_t orig_oparg = oparg;  // For OPARG_TOP/BOTTOM
                    for (int i = 0; i < expansion->nuops; i++) {
                        oparg = orig_oparg;
                        uint32_t uop = expansion->uops[i].uop;
                        uint64_t operand = 0;
                        // Add one to account for the actual opcode/oparg pair:
                        int offset = expansion->uops[i].offset + 1;
                        switch (expansion->uops[i].size) {
                            case OPARG_FULL:
                                break;
                            case OPARG_CACHE_1:
                                operand = read_u16(&instructions[i1 + offset].cache);
                                break;
                            case OPARG_CACHE_2:
                                operand = read_u32(&instructions[i1 + offset].cache);
                                break;
                            case OPARG_CACHE_4:
                                operand = read_u64(&instructions[i1 + offset].cache);
                                break;
                            case OPARG_TOP:
                                oparg = orig_oparg >> 4;
                                break;
                            case OPARG_BOTTOM:
                                oparg = orig_oparg & 0xF;
                                break;
                            case OPARG_SAVE_RETURN_OFFSET:
                                assert(uop == _SAVE_RETURN_OFFSET);
                                oparg = offset;
                                break;
                            case OPARG_REPLACED:
                                uop = _PyUOp_Replacements[uop];
                                uint32_t target = i1 + SIZE(opcode) + oparg;
                                if (uop == _FOR_ITER_TIER_TWO ||
                                    uop == _GUARD_NOT_EXHAUSTED_LIST ||
                                    uop == _GUARD_NOT_EXHAUSTED_RANGE ||
                                    uop == _GUARD_NOT_EXHAUSTED_TUPLE)
                                {
                                    assert(_Py_GetBaseCodeUnit(code, target).op.code == END_FOR);
                                    target++;
                                    assert(_Py_GetBaseCodeUnit(code, target).op.code == POP_ITER);
                                }
                                ADD_UOP_JUMP(uop, oparg, operand, target, start);
                                goto skip;
                            default:
                                Py_FatalError("garbled expansion");
                        }
                        if (uop == _BINARY_OP_INPLACE_ADD_UNICODE) {
                            assert(i + 1 == expansion->nuops);
                            assert(_Py_GetBaseCodeUnit(code, i1 + SIZE(opcode)).op.code == STORE_FAST);
                            _Py_CODEUNIT next_instr = instructions[i1 + SIZE(opcode)];
                            operand = next_instr.op.arg;
                        }
                        ADD_UOP_TARGET(uop, oparg, operand, start);
                    skip:
                        ;
                    }
                }
                else {
                    ADD_UOP_TARGET(_DEOPT, 0, 0, start);
                }
                break;
        }
    loop:
        if (MIN_INSTRUMENTED_OPCODE <= opcode) {
            goto quit;
        }
        i1 += SIZE(opcode);
        if (opcode == BINARY_OP_INPLACE_ADD_UNICODE) {
            assert(_Py_GetBaseCodeUnit(code, i1).op.code == STORE_FAST);
            i1 += SIZE(STORE_FAST);
        }
        if (opcode == CALL_LIST_APPEND) {
            assert(_Py_GetBaseCodeUnit(code, i1).op.code == POP_TOP);
            i1 += SIZE(POP_TOP);
        }
    }
    assert(i1 == j1);
    // XXX: Optimize
    bool *info = PyMem_Calloc(i2, sizeof(bool));
    if (info == NULL) {
        goto error;
    }
    for (size_t i = 0; i < i2; i++) {
        _PyUOpInstruction *uop = &trace[i];
        if (uop->format == UOP_FORMAT_JUMP) {
            uintptr_t target = offsets[uop->jump_target];
            assert(target != UINTPTR_MAX);
            info[target] = true;
        }
    }
    bool may_have_escaped = false;
    ssize_t last_set_ip = -1;
    for (size_t i = 0; i < i2; i++) {
        int opcode = trace[i].opcode;
        if (info[i]) {
            may_have_escaped = true;
            last_set_ip = -1;
        }
        switch (opcode) {
            case _SET_IP:
                trace[i].opcode = _NOP;
                last_set_ip = i;
                break;
            case _CHECK_VALIDITY:
                if (may_have_escaped) {
                    may_have_escaped = false;
                }
                else {
                    trace[i].opcode = _NOP;
                }
                break;
            case _CHECK_VALIDITY_AND_SET_IP:
                if (may_have_escaped) {
                    may_have_escaped = false;
                    trace[i].opcode = _CHECK_VALIDITY;
                }
                else {
                    trace[i].opcode = _NOP;
                }
                last_set_ip = i;
                break;
            // case _POP_TOP:
            // {
            //     _PyUOpInstruction *last = &trace[i-1];
            //     while (last->opcode == _NOP) {
            //         last--;
            //     }
            //     if (last->opcode == _LOAD_CONST_INLINE  ||
            //         last->opcode == _LOAD_CONST_INLINE_BORROW ||
            //         last->opcode == _LOAD_FAST ||
            //         last->opcode == _COPY
            //     ) {
            //         last->opcode = _NOP;
            //         trace[i].opcode = _NOP;
            //     }
            //     if (last->opcode == _REPLACE_WITH_TRUE) {
            //         last->opcode = _NOP;
            //     }
            //     break;
            // }
            case _DEOPT:
            case _ERROR_POP_N:
            case _EXIT_TRACE:
            case _JUMP_TO_TOP:
                may_have_escaped = false;
                last_set_ip = -1;
                break;
            default:
            {
                /* _PUSH_FRAME doesn't escape or error, but it
                * does need the IP for the return address */
                bool needs_ip = opcode == _PUSH_FRAME || opcode == _RETURN_GENERATOR || opcode == _YIELD_VALUE;
                if (needs_ip || (_PyUop_Flags[opcode] & HAS_ESCAPES_FLAG)) {
                    needs_ip = true;
                    may_have_escaped = true;
                }
                if (needs_ip && 0 <= last_set_ip) {
                    if (trace[last_set_ip].opcode == _CHECK_VALIDITY) {
                        trace[last_set_ip].opcode = _CHECK_VALIDITY_AND_SET_IP;
                    }
                    else {
                        assert(trace[last_set_ip].opcode == _NOP);
                        trace[last_set_ip].opcode = _SET_IP;
                    }
                    last_set_ip = -1;
                }
            }
        }
    }
    PyMem_Free(info);
    ////////////////////////////////////////////////////////////////////////////
    int32_t current_jump = -1;
    int32_t current_jump_target = -1;
    int32_t current_error = -1;
    int32_t current_error_target = -1;
    int32_t current_popped = -1;
    int32_t current_exit_op = -1;
    // // Can't do this because it messes up offsets:
    // /* Leaving in NOPs slows down the interpreter and messes up the stats */
    // _PyUOpInstruction *new = &trace[0];
    // for (size_t i = 0; i < i2; i++) {
    //     _PyUOpInstruction *uop = &trace[i];
    //     if (uop->opcode != _NOP) {
    //         if (new != uop) {
    //             *new = *uop;
    //         }
    //         new++;
    //     }
    // }
    // i2 = new - trace;
    for (size_t i = 0; i < i2; i++) {
        int opcode = trace[i].opcode;
        int32_t target;
        if (trace[i].format == UOP_FORMAT_JUMP) {
            target = (int32_t)uop_get_error_target(&trace[i]);
            assert(!(_PyUop_Flags[opcode] & (HAS_EXIT_FLAG | HAS_DEOPT_FLAG)));
            assert(offsets[trace[i].jump_target] != UINTPTR_MAX);
            trace[i].jump_target = offsets[trace[i].jump_target];
        }
        else {
            target = (int32_t)uop_get_target(&trace[i]);
            if (_PyUop_Flags[opcode] & (HAS_EXIT_FLAG | HAS_DEOPT_FLAG)) {
                // uint16_t exit_op = (_PyUop_Flags[opcode] & HAS_EXIT_FLAG) ? _EXIT_TRACE : _DEOPT;
                uint16_t exit_op = _DEOPT;  // XXX
                if (target != current_jump_target || current_exit_op != exit_op) {
                    current_exit_op = exit_op;
                    current_jump_target = target;
                    current_jump = i2;
                    ADD_UOP_TARGET(exit_op, 0, 0, target);
                }
                trace[i].format = UOP_FORMAT_JUMP;
                trace[i].jump_target = current_jump;
                trace[i].error_target = 0;
            }
        }
        if (_PyUop_Flags[opcode] & HAS_ERROR_FLAG) {
            int popped = (_PyUop_Flags[opcode] & HAS_ERROR_NO_POP_FLAG) ? 0 : _PyUop_num_popped(opcode, trace[i].oparg);
            if (target != current_error_target || popped != current_popped) {
                current_popped = popped;
                current_error_target = target;
                current_error = i2;
                ADD_UOP_TARGET(_ERROR_POP_N, 0, target, 0);
            }
            if (trace[i].format == UOP_FORMAT_TARGET) {
                trace[i].format = UOP_FORMAT_JUMP;
                trace[i].jump_target = 0;
            }
            trace[i].error_target = current_error;
        }
    }
    // printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    // PyObject_Print((PyObject *)code, stdout, 0);
    // printf("\n");
    // for (size_t i = 0; i < i2; i++) {
    //     printf("%ld: ", i);
    //     _PyUOpPrint(&trace[i]);
    //     printf("\n");
    // }
    // printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    *offsets_p = offsets;
    *trace_p = trace;
    return i2;
quit:
    PyMem_Free(offsets);
    PyMem_Free(trace);
    return 0;
error:
    PyMem_Free(offsets);
    PyMem_Free(trace);
    return -1;
 }

#define UNSET_BIT(array, bit) (array[(bit)>>5] &= ~(1<<((bit)&31)))
#define SET_BIT(array, bit) (array[(bit)>>5] |= (1<<((bit)&31)))
#define BIT_IS_SET(array, bit) (array[(bit)>>5] & (1<<((bit)&31)))

/* Count the number of unused uops and exits
*/
static int
count_exits(_PyUOpInstruction *buffer, int length)
{
    int exit_count = 0;
    for (int i = 0; i < length; i++) {
        int opcode = buffer[i].opcode;
        if (opcode == _EXIT_TRACE) {
            exit_count++;
        }
    }
    return exit_count;
}

/* Executor side exits */

static _PyExecutorObject *
allocate_executor(int exit_count, int length)
{
    int size = exit_count*sizeof(_PyExitData) + length*sizeof(_PyUOpInstruction);
    _PyExecutorObject *res = PyObject_GC_NewVar(_PyExecutorObject, &_PyUOpExecutor_Type, size);
    if (res == NULL) {
        return NULL;
    }
    res->trace = (_PyUOpInstruction *)(res->exits + exit_count);
    res->code_size = length;
    res->exit_count = exit_count;
    return res;
}

#ifdef Py_DEBUG

#define CHECK(PRED) \
if (!(PRED)) { \
    printf(#PRED " at %d\n", i); \
    assert(0); \
}

static int
target_unused(int opcode)
{
    return (_PyUop_Flags[opcode] & (HAS_ERROR_FLAG | HAS_EXIT_FLAG | HAS_DEOPT_FLAG)) == 0;
}

static void
sanity_check(_PyExecutorObject *executor)
{
    for (uint32_t i = 0; i < executor->exit_count; i++) {
        _PyExitData *exit = &executor->exits[i];
        CHECK(exit->target < (1 << 25));
    }
    // bool ended = false;
    uint32_t i = 0;
    CHECK(executor->trace[0].opcode == _START_EXECUTOR);
    for (; i < executor->code_size; i++) {
        const _PyUOpInstruction *inst = &executor->trace[i];
        uint16_t opcode = inst->opcode;
        CHECK(opcode <= MAX_UOP_ID);
        CHECK(_PyOpcode_uop_name[opcode] != NULL);
        switch(inst->format) {
            case UOP_FORMAT_TARGET:
                CHECK(target_unused(opcode));
                break;
            case UOP_FORMAT_JUMP:
                CHECK(inst->jump_target < executor->code_size);
                break;
        }
        if (_PyUop_Flags[opcode] & HAS_ERROR_FLAG) {
            CHECK(inst->format == UOP_FORMAT_JUMP);
            CHECK(inst->error_target < executor->code_size);
        }
        // if (is_terminator(inst)) {
        //     ended = true;
        //     i++;
        //     break;
        // }
    }
    // CHECK(ended);
    // for (; i < executor->code_size; i++) {
    //     const _PyUOpInstruction *inst = &executor->trace[i];
    //     uint16_t opcode = inst->opcode;
    //     CHECK(
    //         opcode == _DEOPT ||
    //         opcode == _EXIT_TRACE ||
    //         opcode == _ERROR_POP_N);
    // }
}

#undef CHECK
#endif

/* Makes an executor from a buffer of uops.
 * Account for the buffer having gaps and NOPs by computing a "used"
 * bit vector and only copying the used uops. Here "used" means reachable
 * and not a NOP.
 */
static _PyExecutorObject *
make_executor_from_uops(_PyUOpInstruction *buffer, int length, const _PyBloomFilter *dependencies)
{
    int exit_count = count_exits(buffer, length);
    _PyExecutorObject *executor = allocate_executor(exit_count, length);
    if (executor == NULL) {
        return NULL;
    }

    /* Initialize exits */
    for (int i = 0; i < exit_count; i++) {
        executor->exits[i].executor = NULL;
        executor->exits[i].temperature = initial_temperature_backoff_counter();
    }
    int next_exit = exit_count-1;
    _PyUOpInstruction *dest = (_PyUOpInstruction *)&executor->trace[length];
    assert(buffer[0].opcode == _START_EXECUTOR);
    buffer[0].operand0 = (uint64_t)executor;
    for (int i = length-1; i >= 0; i--) {
        int opcode = buffer[i].opcode;
        dest--;
        *dest = buffer[i];
        assert(opcode != _POP_JUMP_IF_FALSE && opcode != _POP_JUMP_IF_TRUE);
        if (opcode == _EXIT_TRACE) {
            _PyExitData *exit = &executor->exits[next_exit];
            exit->target = buffer[i].target;
            dest->operand0 = (uint64_t)exit;
            next_exit--;
        }
    }
    assert(next_exit == -1);
    assert(dest == executor->trace);
    assert(dest->opcode == _START_EXECUTOR);
    _Py_ExecutorInit(executor, dependencies);
#ifdef Py_DEBUG
    char *python_lltrace = Py_GETENV("PYTHON_LLTRACE");
    int lltrace = 0;
    if (python_lltrace != NULL && *python_lltrace >= '0') {
        lltrace = *python_lltrace - '0';  // TODO: Parse an int and all that
    }
    if (lltrace >= 2) {
        printf("Optimized trace (length %d):\n", length);
        for (int i = 0; i < length; i++) {
            printf("%4d OPTIMIZED: ", i);
            _PyUOpPrint(&executor->trace[i]);
            printf("\n");
        }
    }
    sanity_check(executor);
#endif
    _PyObject_GC_TRACK(executor);
    return executor;
}

#ifdef Py_STATS
/* Returns the effective trace length.
 * Ignores NOPs and trailing exit and error handling.*/
int effective_trace_length(_PyUOpInstruction *buffer, int length)
{
    int nop_count = 0;
    for (int i = 0; i < length; i++) {
        int opcode = buffer[i].opcode;
        if (opcode == _NOP) {
            nop_count++;
        }
        if (is_terminator(&buffer[i])) {
            return i+1-nop_count;
        }
    }
    Py_FatalError("No terminating instruction");
    Py_UNREACHABLE();
}
#endif

static int
uop_optimize(
    _PyInterpreterFrame *frame,
    _Py_CODEUNIT *instr,
    _PyExecutorObject **exec_ptr,
    int curr_stackentries)
{
    _PyBloomFilter dependencies;
    _Py_BloomFilter_Init(&dependencies);
    _PyUOpInstruction *buffer;
    uintptr_t *offsets;
    OPT_STAT_INC(attempts);
    int length = translate_bytecode_to_trace(frame, instr, &buffer, &offsets, &dependencies);
    if (length <= 0) {
        // Error or nothing translated
        return length;
    }
    // assert(length < UOP_MAX_TRACE_LENGTH);
    // OPT_STAT_INC(traces_created);
    // char *env_var = Py_GETENV("PYTHON_UOPS_OPTIMIZE");
    // if (env_var == NULL || *env_var == '\0' || *env_var > '0') {
    //     length = _Py_uop_analyze_and_optimize(frame, buffer,
    //                                        length,
    //                                        curr_stackentries, &dependencies);
    //     if (length <= 0) {
    //         return length;
    //     }
    // }
    assert(length >= 1);
    /* Fix up */
    for (int pc = 0; pc < length; pc++) {
        int opcode = buffer[pc].opcode;
        int oparg = buffer[pc].oparg;
        if (_PyUop_Flags[opcode] & HAS_OPARG_AND_1_FLAG) {
            buffer[pc].opcode = opcode + 1 + (oparg & 1);
            assert(strncmp(_PyOpcode_uop_name[buffer[pc].opcode], _PyOpcode_uop_name[opcode], strlen(_PyOpcode_uop_name[opcode])) == 0);
        }
        else if (oparg < _PyUop_Replication[opcode]) {
            buffer[pc].opcode = opcode + oparg + 1;
            assert(strncmp(_PyOpcode_uop_name[buffer[pc].opcode], _PyOpcode_uop_name[opcode], strlen(_PyOpcode_uop_name[opcode])) == 0);
        }
        assert(_PyOpcode_uop_name[buffer[pc].opcode]);
    }
    OPT_HIST(effective_trace_length(buffer, length), optimized_trace_length_hist);
    // length = prepare_for_execution(buffer, length);
    _PyExecutorObject *executor = make_executor_from_uops(buffer, length, &dependencies);
    if (executor == NULL) {
        return -1;
    }
    executor->jit_offsets = offsets;
    // assert(length <= UOP_MAX_TRACE_LENGTH);
    *exec_ptr = executor;
    return 1;
}


/*****************************************
 *        Executor management
 ****************************************/

/* We use a bloomfilter with k = 6, m = 256
 * The choice of k and the following constants
 * could do with a more rigorous analysis,
 * but here is a simple analysis:
 *
 * We want to keep the false positive rate low.
 * For n = 5 (a trace depends on 5 objects),
 * we expect 30 bits set, giving a false positive
 * rate of (30/256)**6 == 2.5e-6 which is plenty
 * good enough.
 *
 * However with n = 10 we expect 60 bits set (worst case),
 * giving a false positive of (60/256)**6 == 0.0001
 *
 * We choose k = 6, rather than a higher number as
 * it means the false positive rate grows slower for high n.
 *
 * n = 5, k = 6 => fp = 2.6e-6
 * n = 5, k = 8 => fp = 3.5e-7
 * n = 10, k = 6 => fp = 1.6e-4
 * n = 10, k = 8 => fp = 0.9e-4
 * n = 15, k = 6 => fp = 0.18%
 * n = 15, k = 8 => fp = 0.23%
 * n = 20, k = 6 => fp = 1.1%
 * n = 20, k = 8 => fp = 2.3%
 *
 * The above analysis assumes perfect hash functions,
 * but those don't exist, so the real false positive
 * rates may be worse.
 */

#define K 6

#define SEED 20221211

/* TO DO -- Use more modern hash functions with better distribution of bits */
static uint64_t
address_to_hash(void *ptr) {
    assert(ptr != NULL);
    uint64_t uhash = SEED;
    uintptr_t addr = (uintptr_t)ptr;
    for (int i = 0; i < SIZEOF_VOID_P; i++) {
        uhash ^= addr & 255;
        uhash *= (uint64_t)PyHASH_MULTIPLIER;
        addr >>= 8;
    }
    return uhash;
}

void
_Py_BloomFilter_Init(_PyBloomFilter *bloom)
{
    for (int i = 0; i < _Py_BLOOM_FILTER_WORDS; i++) {
        bloom->bits[i] = 0;
    }
}

/* We want K hash functions that each set 1 bit.
 * A hash function that sets 1 bit in M bits can be trivially
 * derived from a log2(M) bit hash function.
 * So we extract 8 (log2(256)) bits at a time from
 * the 64bit hash. */
void
_Py_BloomFilter_Add(_PyBloomFilter *bloom, void *ptr)
{
    uint64_t hash = address_to_hash(ptr);
    assert(K <= 8);
    for (int i = 0; i < K; i++) {
        uint8_t bits = hash & 255;
        bloom->bits[bits >> 5] |= (1 << (bits&31));
        hash >>= 8;
    }
}

static bool
bloom_filter_may_contain(_PyBloomFilter *bloom, _PyBloomFilter *hashes)
{
    for (int i = 0; i < _Py_BLOOM_FILTER_WORDS; i++) {
        if ((bloom->bits[i] & hashes->bits[i]) != hashes->bits[i]) {
            return false;
        }
    }
    return true;
}

static void
link_executor(_PyExecutorObject *executor)
{
    PyInterpreterState *interp = _PyInterpreterState_GET();
    _PyExecutorLinkListNode *links = &executor->vm_data.links;
    _PyExecutorObject *head = interp->executor_list_head;
    if (head == NULL) {
        interp->executor_list_head = executor;
        links->previous = NULL;
        links->next = NULL;
    }
    else {
        assert(head->vm_data.links.previous == NULL);
        links->previous = NULL;
        links->next = head;
        head->vm_data.links.previous = executor;
        interp->executor_list_head = executor;
    }
    executor->vm_data.linked = true;
    /* executor_list_head must be first in list */
    assert(interp->executor_list_head->vm_data.links.previous == NULL);
}

static void
unlink_executor(_PyExecutorObject *executor)
{
    if (!executor->vm_data.linked) {
        return;
    }
    _PyExecutorLinkListNode *links = &executor->vm_data.links;
    assert(executor->vm_data.valid);
    _PyExecutorObject *next = links->next;
    _PyExecutorObject *prev = links->previous;
    if (next != NULL) {
        next->vm_data.links.previous = prev;
    }
    if (prev != NULL) {
        prev->vm_data.links.next = next;
    }
    else {
        // prev == NULL implies that executor is the list head
        PyInterpreterState *interp = PyInterpreterState_Get();
        assert(interp->executor_list_head == executor);
        interp->executor_list_head = next;
    }
    executor->vm_data.linked = false;
}

/* This must be called by optimizers before using the executor */
void
_Py_ExecutorInit(_PyExecutorObject *executor, const _PyBloomFilter *dependency_set)
{
    executor->vm_data.valid = true;
    for (int i = 0; i < _Py_BLOOM_FILTER_WORDS; i++) {
        executor->vm_data.bloom.bits[i] = dependency_set->bits[i];
    }
    link_executor(executor);
}

/* Detaches the executor from the code object (if any) that
 * holds a reference to it */
void
_Py_ExecutorDetach(_PyExecutorObject *executor)
{
    PyCodeObject *code = executor->vm_data.code;
    if (code == NULL) {
        return;
    }
    _Py_CODEUNIT *instruction = &_PyCode_CODE(code)[executor->vm_data.index];
    assert(instruction->op.code == ENTER_EXECUTOR);
    int index = instruction->op.arg;
    assert(code->co_executors->executors[index] == executor);
    instruction->op.code = executor->vm_data.opcode;
    instruction->op.arg = executor->vm_data.oparg;
    executor->vm_data.code = NULL;
    code->co_executors->executors[index] = NULL;
    Py_DECREF(executor);
}

static int
executor_clear(_PyExecutorObject *executor)
{
    if (!executor->vm_data.valid) {
        return 0;
    }
    assert(executor->vm_data.valid == 1);
    unlink_executor(executor);
    executor->vm_data.valid = 0;
    /* It is possible for an executor to form a reference
     * cycle with itself, so decref'ing a side exit could
     * free the executor unless we hold a strong reference to it
     */
    Py_INCREF(executor);
    for (uint32_t i = 0; i < executor->exit_count; i++) {
        executor->exits[i].temperature = initial_unreachable_backoff_counter();
        Py_CLEAR(executor->exits[i].executor);
    }
    _Py_ExecutorDetach(executor);
    Py_DECREF(executor);
    return 0;
}

void
_Py_Executor_DependsOn(_PyExecutorObject *executor, void *obj)
{
    assert(executor->vm_data.valid);
    _Py_BloomFilter_Add(&executor->vm_data.bloom, obj);
}

/* Invalidate all executors that depend on `obj`
 * May cause other executors to be invalidated as well
 */
void
_Py_Executors_InvalidateDependency(PyInterpreterState *interp, void *obj, int is_invalidation)
{
    _PyBloomFilter obj_filter;
    _Py_BloomFilter_Init(&obj_filter);
    _Py_BloomFilter_Add(&obj_filter, obj);
    /* Walk the list of executors */
    /* TO DO -- Use a tree to avoid traversing as many objects */
    PyObject *invalidate = PyList_New(0);
    if (invalidate == NULL) {
        goto error;
    }
    /* Clearing an executor can deallocate others, so we need to make a list of
     * executors to invalidate first */
    for (_PyExecutorObject *exec = interp->executor_list_head; exec != NULL;) {
        assert(exec->vm_data.valid);
        _PyExecutorObject *next = exec->vm_data.links.next;
        if (bloom_filter_may_contain(&exec->vm_data.bloom, &obj_filter) &&
            PyList_Append(invalidate, (PyObject *)exec))
        {
            goto error;
        }
        exec = next;
    }
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(invalidate); i++) {
        _PyExecutorObject *exec = (_PyExecutorObject *)PyList_GET_ITEM(invalidate, i);
        executor_clear(exec);
        if (is_invalidation) {
            OPT_STAT_INC(executors_invalidated);
        }
    }
    Py_DECREF(invalidate);
    return;
error:
    PyErr_Clear();
    Py_XDECREF(invalidate);
    // If we're truly out of memory, wiping out everything is a fine fallback:
    _Py_Executors_InvalidateAll(interp, is_invalidation);
}

/* Invalidate all executors */
void
_Py_Executors_InvalidateAll(PyInterpreterState *interp, int is_invalidation)
{
    while (interp->executor_list_head) {
        _PyExecutorObject *executor = interp->executor_list_head;
        assert(executor->vm_data.valid == 1 && executor->vm_data.linked == 1);
        if (executor->vm_data.code) {
            // Clear the entire code object so its co_executors array be freed:
            _PyCode_Clear_Executors(executor->vm_data.code);
        }
        else {
            executor_clear(executor);
        }
        if (is_invalidation) {
            OPT_STAT_INC(executors_invalidated);
        }
    }
}

void
_Py_Executors_InvalidateCold(PyInterpreterState *interp)
{
    /* Walk the list of executors */
    /* TO DO -- Use a tree to avoid traversing as many objects */
    PyObject *invalidate = PyList_New(0);
    if (invalidate == NULL) {
        goto error;
    }

    /* Clearing an executor can deallocate others, so we need to make a list of
     * executors to invalidate first */
    for (_PyExecutorObject *exec = interp->executor_list_head; exec != NULL;) {
        assert(exec->vm_data.valid);
        _PyExecutorObject *next = exec->vm_data.links.next;

        if (!exec->vm_data.warm && PyList_Append(invalidate, (PyObject *)exec) < 0) {
            goto error;
        }
        else {
            exec->vm_data.warm = false;
        }

        exec = next;
    }
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(invalidate); i++) {
        _PyExecutorObject *exec = (_PyExecutorObject *)PyList_GET_ITEM(invalidate, i);
        executor_clear(exec);
    }
    Py_DECREF(invalidate);
    return;
error:
    PyErr_Clear();
    Py_XDECREF(invalidate);
    // If we're truly out of memory, wiping out everything is a fine fallback
    _Py_Executors_InvalidateAll(interp, 0);
}

static void
write_str(PyObject *str, FILE *out)
{
    // Encode the Unicode object to the specified encoding
    PyObject *encoded_obj = PyUnicode_AsEncodedString(str, "utf8", "strict");
    if (encoded_obj == NULL) {
        PyErr_Clear();
        return;
    }
    const char *encoded_str = PyBytes_AsString(encoded_obj);
    Py_ssize_t encoded_size = PyBytes_Size(encoded_obj);
    fwrite(encoded_str, 1, encoded_size, out);
    Py_DECREF(encoded_obj);
}

static int
find_line_number(PyCodeObject *code, _PyExecutorObject *executor)
{
    int code_len = (int)Py_SIZE(code);
    for (int i = 0; i < code_len; i++) {
        _Py_CODEUNIT *instr = &_PyCode_CODE(code)[i];
        int opcode = instr->op.code;
        if (opcode == ENTER_EXECUTOR) {
            _PyExecutorObject *exec = code->co_executors->executors[instr->op.arg];
            if (exec == executor) {
                return PyCode_Addr2Line(code, i*2);
            }
        }
        i += _PyOpcode_Caches[_Py_GetBaseCodeUnit(code, i).op.code];
    }
    return -1;
}

/* Writes the node and outgoing edges for a single tracelet in graphviz format.
 * Each tracelet is presented as a table of the uops it contains.
 * If Py_STATS is enabled, execution counts are included.
 *
 * https://graphviz.readthedocs.io/en/stable/manual.html
 * https://graphviz.org/gallery/
 */
static void
executor_to_gv(_PyExecutorObject *executor, FILE *out)
{
    PyCodeObject *code = executor->vm_data.code;
    fprintf(out, "executor_%p [\n", executor);
    fprintf(out, "    shape = none\n");

    /* Write the HTML table for the uops */
    fprintf(out, "    label = <<table border=\"0\" cellspacing=\"0\">\n");
    fprintf(out, "        <tr><td port=\"start\" border=\"1\" ><b>Executor</b></td></tr>\n");
    if (code == NULL) {
        fprintf(out, "        <tr><td border=\"1\" >No code object</td></tr>\n");
    }
    else {
        fprintf(out, "        <tr><td  border=\"1\" >");
        write_str(code->co_qualname, out);
        int line = find_line_number(code, executor);
        fprintf(out, ": %d</td></tr>\n", line);
    }
    for (uint32_t i = 0; i < executor->code_size; i++) {
        /* Write row for uop.
         * The `port` is a marker so that outgoing edges can
         * be placed correctly. If a row is marked `port=17`,
         * then the outgoing edge is `{EXEC_NAME}:17 -> {TARGET}`
         * https://graphviz.readthedocs.io/en/stable/manual.html#node-ports-compass
         */
        _PyUOpInstruction const *inst = &executor->trace[i];
        const char *opname = _PyOpcode_uop_name[inst->opcode];
#ifdef Py_STATS
        fprintf(out, "        <tr><td port=\"i%d\" border=\"1\" >%s -- %" PRIu64 "</td></tr>\n", i, opname, inst->execution_count);
#else
        fprintf(out, "        <tr><td port=\"i%d\" border=\"1\" >%s</td></tr>\n", i, opname);
#endif
        if (inst->opcode == _EXIT_TRACE || inst->opcode == _JUMP_TO_TOP) {
            break;
        }
    }
    fprintf(out, "    </table>>\n");
    fprintf(out, "]\n\n");

    /* Write all the outgoing edges */
    for (uint32_t i = 0; i < executor->code_size; i++) {
        _PyUOpInstruction const *inst = &executor->trace[i];
        uint16_t flags = _PyUop_Flags[inst->opcode];
        _PyExitData *exit = NULL;
        if (inst->opcode == _EXIT_TRACE) {
            exit = (_PyExitData *)inst->operand0;
        }
        else if (flags & HAS_EXIT_FLAG) {
            assert(inst->format == UOP_FORMAT_JUMP);
            _PyUOpInstruction const *exit_inst = &executor->trace[inst->jump_target];
            assert(exit_inst->opcode == _EXIT_TRACE);
            exit = (_PyExitData *)exit_inst->operand0;
        }
        if (exit != NULL && exit->executor != NULL) {
            fprintf(out, "executor_%p:i%d -> executor_%p:start\n", executor, i, exit->executor);
        }
        if (inst->opcode == _EXIT_TRACE || inst->opcode == _JUMP_TO_TOP) {
            break;
        }
    }
}

/* Write the graph of all the live tracelets in graphviz format. */
int
_PyDumpExecutors(FILE *out)
{
    fprintf(out, "digraph ideal {\n\n");
    fprintf(out, "    rankdir = \"LR\"\n\n");
    PyInterpreterState *interp = PyInterpreterState_Get();
    for (_PyExecutorObject *exec = interp->executor_list_head; exec != NULL;) {
        executor_to_gv(exec, out);
        exec = exec->vm_data.links.next;
    }
    fprintf(out, "}\n\n");
    return 0;
}

#else

int
_PyDumpExecutors(FILE *out)
{
    PyErr_SetString(PyExc_NotImplementedError, "No JIT available");
    return -1;
}

#endif /* _Py_TIER2 */
