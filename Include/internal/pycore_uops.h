#ifndef Py_INTERNAL_UOPS_H
#define Py_INTERNAL_UOPS_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

////////////////////////////////////////////////////////////////////////////////

#define UOP_CHECK_TRACING()      _uop_check_tracing(cframe, &opcode)
#define UOP_DECREF(O)            _uop_decref(_PyObject_CAST((O)))
#define UOP_DECREF_FLOAT(O)      _uop_decref_float(_PyObject_CAST((O)))
#define UOP_DECREF_IMMORTAL(O)   _uop_decref_immortal(_PyObject_CAST((O)))
#define UOP_DECREF_LONG(O)       _uop_decref_long(_PyObject_CAST((O)))
#define UOP_DECREF_UNICODE(O)    _uop_decref_unicode(_PyObject_CAST((O)))
#define UOP_DISPATCH()           _uop_dispatch()
#define UOP_EXTEND_OPARG()       _uop_extend_oparg(&oparg, next_instr)
#define UOP_GET_CONST(O, I)      _uop_get_const(&(O), consts, (I))
#define UOP_GET_FAST(O, I)       _uop_get_fast(&(O), frame, (I))
#define UOP_INCREF(O)            _uop_incref(_PyObject_CAST((O)))
#define UOP_JUMP(I)              _uop_jump(&next_instr, (I))
#define UOP_LINK_FRAME(F)        _uop_link_frame((F), &frame, &cframe)
#define UOP_LLTRACE()            _uop_lltrace()
#define UOP_NEXT_OPARG()         _uop_next_oparg(next_instr, &oparg)
#define UOP_NEXT_OPCODE()        _uop_next_opcode(next_instr, &opcode)
#define UOP_STACK_ADJUST(I)      _uop_stack_adjust(&stack_pointer, (I))
#define UOP_STACK_GET(O, I)      _uop_stack_get(&(O), stack_pointer, (I))
#define UOP_STACK_SET(I, O)      _uop_stack_set(stack_pointer, (I), _PyObject_CAST((O)))
#define UOP_STAT_DEFERRED(I)     _uop_stat_deferred((I))
#define UOP_STAT_HIT(I)          _uop_stat_hit((I))
#define UOP_STORE_FAST(I, O)     _uop_store_fast(frame, (I), _PyObject_CAST((O)))
#define UOP_UNREACHABLE()        _uop_unreachable()
#define UOP_UPDATE_STATS()       _uop_update_stats()
#define UOP_WARMUP()             _uop_warmup(frame)
#define UOP_WRITE_PREV_INSTR()   _uop_write_prev_instr(frame, next_instr)
#define UOP_WRITE_STACK_TOP()    _uop_write_stack_top(frame, stack_pointer)

////////////////////////////////////////////////////////////////////////////////

static inline Py_ALWAYS_INLINE void
_uop_check_tracing(_PyCFrame cframe, uint8_t *opcode_p)
{
    assert(cframe.use_tracing == 0 || cframe.use_tracing == 255);
    *opcode_p |= cframe.use_tracing;
#ifdef WITH_DTRACE
    *opcode_p |= PyDTrace_LINE_ENABLED() ? 255 : 0;
#endif
}

static inline Py_ALWAYS_INLINE void
_uop_decref(PyObject *o)
{
    Py_DECREF(o);
}

static inline Py_ALWAYS_INLINE void
_uop_decref_float(PyObject *o)
{
    _Py_DECREF_SPECIALIZED(o, _PyFloat_ExactDealloc);
}

static inline Py_ALWAYS_INLINE void
_uop_decref_immortal(PyObject *o)
{
    _Py_DECREF_NO_DEALLOC(o);
}

static inline Py_ALWAYS_INLINE void
_uop_decref_long(PyObject *o)
{
    _Py_DECREF_SPECIALIZED(o, (destructor)PyObject_Free);
}

static inline Py_ALWAYS_INLINE void
_uop_decref_unicode(PyObject *o)
{
    _Py_DECREF_SPECIALIZED(o, _PyUnicode_ExactDealloc);
}

#define _uop_dispatch() DISPATCH_GOTO()

static inline Py_ALWAYS_INLINE void
_uop_extend_oparg(int *oparg_p, _Py_CODEUNIT *next_instr)
{
    *oparg_p <<= 8;
    *oparg_p |= _Py_OPARG(*next_instr);
}

static inline Py_ALWAYS_INLINE void
_uop_get_const(PyObject **o_p, PyObject *consts, int i)
{
    *o_p = PyTuple_GET_ITEM(consts, i);
}

static inline Py_ALWAYS_INLINE void
_uop_get_fast(PyObject **o_p, _PyInterpreterFrame *frame, int i)
{
    *o_p = frame->localsplus[i];
}

static inline Py_ALWAYS_INLINE void
_uop_get_name(PyObject **o_p, PyObject *names, int i)
{
    *o_p = PyTuple_GET_ITEM(names, i);
}

static inline Py_ALWAYS_INLINE void
_uop_incref(PyObject *o)
{
    Py_INCREF(o);
}

static inline Py_ALWAYS_INLINE void
_uop_jump(_Py_CODEUNIT **next_instr_p, int i)
{
    *next_instr_p += i;
}

static inline Py_ALWAYS_INLINE void
_uop_link_frame(_PyInterpreterFrame *f, _PyInterpreterFrame **frame_p, _PyCFrame *cframe_p)
{
    f->previous = *frame_p;
    cframe_p->current_frame = *frame_p = f;
}

#define _uop_lltrace() PRE_DISPATCH_GOTO()

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

#define _uop_stat_deferred(I) STAT_INC((I), deferred)

#define _uop_stat_hit(I) STAT_INC((I), hit)

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
    frame->prev_instr = next_instr - 1;
}

static inline Py_ALWAYS_INLINE void
_uop_write_stack_top(_PyInterpreterFrame *frame, PyObject **stack_pointer)
{
    _PyFrame_SetStackPointer(frame, stack_pointer);
}

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif
#endif   /* !Py_INTERNAL_UOPS_H */
