#ifndef Py_INTERNAL_UOPS_H
#define Py_INTERNAL_UOPS_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

////////////////////////////////////////////////////////////////////////////////

#define UOP_CHECK_EVAL_BREAKER() _uop_check_eval_breaker()
#define UOP_CHECK_TRACING()      _uop_check_tracing(cframe, &opcode)
#define UOP_DISPATCH()           _uop_dispatch()
#define UOP_EXTEND_OPARG()       _uop_extend_oparg(&oparg, next_instr)
#define UOP_INCREF()             _uop_incref(stack_pointer)
#define UOP_JUMP(I)              _uop_jump(&next_instr, (I))
#define UOP_LLTRACE()            _uop_lltrace()
#define UOP_LOAD_CONST(O, I)     _uop_load_const(&(O), consts, (I))
#define UOP_LOAD_FAST(O, I)      _uop_load_fast(&(O), frame, (I))
#define UOP_NEXT_OPARG()         _uop_next_oparg(next_instr, &oparg)
#define UOP_NEXT_OPCODE()        _uop_next_opcode(next_instr, &opcode)
#define UOP_STACK_ADJUST(I)      _uop_stack_adjust(&stack_pointer, (I))
#define UOP_STACK_GET(O, I)      _uop_stack_get(&(O), stack_pointer, (I))
#define UOP_STACK_SET(I, O)      _uop_stack_set(stack_pointer, (I), (O))
#define UOP_STORE_FAST(I, O)     _uop_store_fast(frame, (I), (O))
#define UOP_UNREACHABLE()        _uop_unreachable()
#define UOP_UPDATE_STATS()       _uop_update_stats()
#define UOP_WARMUP()             _uop_warmup(frame)
#define UOP_WRITE_PREV_INSTR()   _uop_write_prev_instr(frame, next_instr)

////////////////////////////////////////////////////////////////////////////////

#define _uop_check_eval_breaker() CHECK_EVAL_BREAKER()

static inline Py_ALWAYS_INLINE void
_uop_check_tracing(_PyCFrame cframe, uint8_t *opcode_p)
{
    assert(cframe.use_tracing == 0 || cframe.use_tracing == 255);
    *opcode_p |= cframe.use_tracing;
#ifdef WITH_DTRACE
    *opcode_p |= PyDTrace_LINE_ENABLED() ? 255 : 0;
#endif
}

#define _uop_dispatch() DISPATCH_GOTO()

static inline Py_ALWAYS_INLINE void
_uop_extend_oparg(int *oparg_p, _Py_CODEUNIT *next_instr)
{
    *oparg_p <<= 8;
    *oparg_p |= _Py_OPARG(*next_instr);
}

static inline Py_ALWAYS_INLINE void
_uop_incref(PyObject **stack_pointer)
{
    Py_INCREF(stack_pointer[-1]);
}

static inline Py_ALWAYS_INLINE void
_uop_jump(_Py_CODEUNIT **next_instr_p, int i)
{
    *next_instr_p += i;
}

#define _uop_lltrace() PRE_DISPATCH_GOTO()

static inline Py_ALWAYS_INLINE void
_uop_load_const(PyObject **o_p, PyObject *consts, int i)
{
    *o_p = PyTuple_GET_ITEM(consts, i);
}

static inline Py_ALWAYS_INLINE void
_uop_load_fast(PyObject **o_p, _PyInterpreterFrame *frame, int i)
{
    *o_p = frame->localsplus[i];
}

static inline Py_ALWAYS_INLINE void
_uop_next_oparg(_Py_CODEUNIT *next_instr, int *oparg_p)
{
    *oparg_p = _Py_OPARG(*next_instr);
}

static inline Py_ALWAYS_INLINE void
_uop_next_opcode(_Py_CODEUNIT *next_instr, uint8_t *opcode_p)
{
    *opcode_p = _Py_OPCODE(*next_instr);
}

static inline Py_ALWAYS_INLINE void
_uop_stack_adjust(PyObject ***stack_pointer_p, int i)
{
    *stack_pointer_p += i;
}

static inline Py_ALWAYS_INLINE void
_uop_stack_get(PyObject **o_p, PyObject **stack_pointer, int i)
{
    *o_p = stack_pointer[-i];
}

static inline Py_ALWAYS_INLINE void
_uop_stack_set(PyObject **stack_pointer, int i, PyObject *o)
{
    stack_pointer[-i] = o;
}

static inline Py_ALWAYS_INLINE void
_uop_store_fast(_PyInterpreterFrame *frame, int i, PyObject *o)
{
    frame->localsplus[i] = o;
}

static inline Py_ALWAYS_INLINE void
_uop_unreachable()
{
    Py_UNREACHABLE();
}

#ifdef Py_STATS
    #define _uop_update_stats()                                       \
        do {                                                          \
            OPCODE_EXE_INC(op);                                       \
            if (_py_stats) {                                          \
                _py_stats->opcode_stats[lastopcode].pair_count[op]++; \
            }                                                         \
            lastopcode = op;                                          \
        } while (0)
#else
    #define _uop_update_stats()
#endif

static inline Py_ALWAYS_INLINE void
_uop_warmup(_PyInterpreterFrame *frame)
{
    _PyCode_Warmup(frame->f_code);
}

static inline Py_ALWAYS_INLINE void
_uop_write_prev_instr(_PyInterpreterFrame *frame, _Py_CODEUNIT *next_instr)
{
    frame->prev_instr = next_instr;
}

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif
#endif   /* !Py_INTERNAL_UOPS_H */
