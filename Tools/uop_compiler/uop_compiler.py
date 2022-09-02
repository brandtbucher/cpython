"""
A simple proof-of-concept compiler for a hypothetical set of CPython 3.12 uops.
Specifically, it compiles statements of the form `a = b + c`.

To test:

    $ pytest Tools/uop_compiler/uop_compiler.py

To view the generated assembly:

    $ python
    >>> from Tools.uop_compiler import uop_compiler
    >>> trace = uop_compiler.compile_trace_a()
    <a bunch of assembly gets printed here>

You can then call `trace(uop_compiler.get_interpreter_frame())` from within a
function to run that compiled trace in the current frame. Just make sure you
have at least three locals, all bound! It will return one of three values:

*  1: Success!
*  0: Fail, if a guard fails without error.
* -1: Error... but the ctypes wrapper will just raise instead of returning.

Example:

    >>> def f():
    ...     foo = 42
    ...     bar = 404
    ...     baz = None
    ...     success = trace(uop_compiler.get_interpreter_frame())
    ...     return success, baz
    ... 
    >>> f()
    (1, 446)
"""

import ctypes
import sys
import weakref

# $ pip install git+https://github.com/Maratyszcza/PeachPy
import peachpy
import peachpy.x86_64
import peachpy.x86_64.abi
import peachpy.x86_64.function
import peachpy.x86_64.operand
import pytest

# PeachPy uses ctypes.CFUNCTYPE to load the jitted code, which releases the GIL
# around each call. That's obviously disastrous for us, so we need to patch it
# with ctypes.PYFUNCTYPE, which holds the GIL:
ctypes.CFUNCTYPE = ctypes.PYFUNCTYPE

assert (3, 12) <= sys.version_info

# Constants:
INLINE_CACHE_ENTRIES_BINARY_OP = 1
NB_ADD = 0
OFFSETOF_F_FRAME = 24  # offsetof(PyFrameObject, f_frame)
OFFSETOF_LOCALSPLUS = 72  # offsetof(_PyInterpreterFrame, localsplus)
OFFSETOF_OB_REFCNT = 0  # offsetof(PyObject, ob_refcnt)
OFFSETOF_OB_TYPE = 8  # offsetof(PyObject, ob_type)
OFFSETOF_PREV_INSTR = 56  # offsetof(_PyInterpreterFrame, prev_instr)
SIZEOF__PY_CODEUNIT = 2  # sizeof(Py_ssize_t)
SIZEOF_PYOBJECT_P = 8  # sizeof(PyObject *)

# Types:
R64 = peachpy.x86_64.GeneralPurposeRegister64
M64 = list[peachpy.x86_64.operand.MemoryAddress]
IMM32 = int


def get_api(f: str) -> int:
    """Helper function to get the address of a Python C-API function `f`."""
    api_pointer = ctypes.cast(getattr(ctypes.pythonapi, f), ctypes.c_void_p)
    api_address = api_pointer.value
    assert api_address is not None
    return api_address


def get_interpreter_frame() -> int:
    """Helper function to get the address the current _PyInterpreterFrame."""
    frame_object_address = id(sys._getframe(1))
    f_frame_address = frame_object_address + OFFSETOF_F_FRAME
    f_frame_pointer = ctypes.cast(f_frame_address, ctypes.POINTER(ctypes.c_void_p))
    interpreter_frame_pointer = f_frame_pointer.contents
    interpreter_frame_address = interpreter_frame_pointer.value
    assert interpreter_frame_address is not None
    return interpreter_frame_address


class UopCompiler:
    def __init__(self, function: peachpy.x86_64.Function) -> None:
        self.function = function
        self.frame = peachpy.x86_64.GeneralPurposeRegister64()
        self.next_instr = peachpy.x86_64.GeneralPurposeRegister64()
        self.error = peachpy.x86_64.Label("error")
        self.deopt = peachpy.x86_64.Label("deopt")

    def finalize(self) -> peachpy.x86_64.function.ABIFunction:
        abi = peachpy.x86_64.abi.detect()
        return self.function.finalize(abi)

    def dump(self) -> str:
        return self.finalize().format()

    def compile(self) -> peachpy.x86_64.function.ExecutableFuntion:  # [sic]
        return self.finalize().encode().load()

    def localsplus(self, i: IMM32) -> M64:
        """Helper function to get the location of local variable `i`."""
        return [self.frame + OFFSETOF_LOCALSPLUS + i * SIZEOF_PYOBJECT_P]

    def prologue(self) -> None:
        peachpy.x86_64.LOAD.ARGUMENT(self.frame, self.function.arguments[0])
        peachpy.x86_64.MOV(self.next_instr, [self.frame + OFFSETOF_PREV_INSTR])
        peachpy.x86_64.ADD(self.next_instr, SIZEOF__PY_CODEUNIT)

    def epilogue(self) -> None:
        peachpy.x86_64.RETURN(1)
        peachpy.x86_64.LABEL(self.deopt)
        peachpy.x86_64.RETURN(0)
        peachpy.x86_64.LABEL(self.error)
        peachpy.x86_64.RETURN(-1)

    def call(self, api: str, result: R64 | M64 | None = None, *args: R64 | M64) -> None:
        """
        Helper function to call Python C-API function `api` with arguments
        `args` and store the result in `result`.
        """
        assert len(args) <= 7
        where = peachpy.x86_64.GeneralPurposeRegister64()
        peachpy.x86_64.PUSH(self.frame)
        for source, dest in zip(
            args,
            [
                peachpy.x86_64.rdi,
                peachpy.x86_64.rsi,
                peachpy.x86_64.rdx,
                peachpy.x86_64.rcx,
                peachpy.x86_64.r8,
                peachpy.x86_64.r9,
            ],
        ):
            peachpy.x86_64.MOV(dest, source)
        peachpy.x86_64.MOV(where, get_api(api))
        peachpy.x86_64.CALL(where)
        peachpy.x86_64.POP(self.frame)
        peachpy.x86_64.MOV(self.next_instr, [self.frame + OFFSETOF_PREV_INSTR])
        peachpy.x86_64.ADD(self.next_instr, SIZEOF__PY_CODEUNIT)
        if result is not None:
            peachpy.x86_64.MOV(result, peachpy.x86_64.rax)

    def UOP_BINARY_OP(
        self, o0: R64 | M64, i: int, o1: R64 | M64, o2: R64 | M64
    ) -> None:
        assert i == NB_ADD
        self.call("PyNumber_Add", o0, o1, o2)

    def UOP_BINARY_OP_ADD_UNICODE(
        self, o0: R64 | M64, o1: R64 | M64, o2: R64 | M64
    ) -> None:
        self.call("PyUnicode_Concat", o0, o1, o2)

    def UOP_DECREF(self, o: R64) -> None:
        end = peachpy.x86_64.Label("end")
        peachpy.x86_64.DEC([o + OFFSETOF_OB_REFCNT])
        peachpy.x86_64.JNZ(end)
        self.call("_Py_Dealloc", None, o)
        peachpy.x86_64.LABEL(end)

    def UOP_ERROR_IF_NULL(self, o: R64 | M64) -> None:
        peachpy.x86_64.CMP(o, 0)
        peachpy.x86_64.JE(self.error)

    def UOP_GUARD_UNICODE(self, o: R64 | M64) -> None:
        obj = peachpy.x86_64.GeneralPurposeRegister64()
        unicode = peachpy.x86_64.GeneralPurposeRegister64()
        peachpy.x86_64.MOV(obj, o)
        peachpy.x86_64.MOV(unicode, id(str))
        peachpy.x86_64.CMP([obj + OFFSETOF_OB_TYPE], unicode)
        peachpy.x86_64.JNE(self.deopt)

    def UOP_GET_FAST(self, o: R64, i: IMM32) -> None:
        peachpy.x86_64.MOV(o, self.localsplus(i))

    def UOP_JUMP(self, i: IMM32) -> None:
        peachpy.x86_64.ADD(self.next_instr, i * SIZEOF__PY_CODEUNIT)

    def UOP_STORE_FAST(self, i: IMM32, o: R64):
        peachpy.x86_64.MOV(self.localsplus(i), o)

    def UOP_WRITE_PREV_INSTR(self) -> None:
        prev_instr = peachpy.x86_64.GeneralPurposeRegister64()
        peachpy.x86_64.LEA(prev_instr, [self.next_instr - SIZEOF__PY_CODEUNIT])
        peachpy.x86_64.MOV([self.frame + OFFSETOF_PREV_INSTR], prev_instr)


def compile_trace_a() -> peachpy.x86_64.function.ExecutableFuntion:  # [sic]
    """
    Compile the uops for `a = b + c`, assuming:
    * a: object
    * b: object
    * c: object
    """
    frame = peachpy.Argument(peachpy.ptr(), name="frame")
    with peachpy.x86_64.Function("<trace>", [frame], peachpy.int32_t) as trace:
        c = UopCompiler(trace)
        r_sum = peachpy.x86_64.GeneralPurposeRegister64()
        r_tmp = peachpy.x86_64.GeneralPurposeRegister64()
        c.prologue()
        c.UOP_JUMP(3)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_BINARY_OP(r_sum, NB_ADD, c.localsplus(0), c.localsplus(1))
        c.UOP_ERROR_IF_NULL(r_sum)
        c.UOP_JUMP(INLINE_CACHE_ENTRIES_BINARY_OP + 1)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_GET_FAST(r_tmp, 2)
        c.UOP_STORE_FAST(2, r_sum)
        c.UOP_DECREF(r_tmp)
        c.epilogue()
    print(c.dump())
    return c.compile()


def compile_trace_b() -> peachpy.x86_64.function.ExecutableFuntion:  # [sic]
    """
    Compile the uops for `a = b + c`, assuming:
    * a: NULL
    * b: object
    * c: object
    """
    frame = peachpy.Argument(peachpy.ptr(), name="frame")
    with peachpy.x86_64.Function("<trace>", [frame], peachpy.int32_t) as trace:
        c = UopCompiler(trace)
        c.prologue()
        c.UOP_JUMP(3)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_BINARY_OP(c.localsplus(2), NB_ADD, c.localsplus(0), c.localsplus(1))
        c.UOP_ERROR_IF_NULL(c.localsplus(2))
        c.UOP_JUMP(INLINE_CACHE_ENTRIES_BINARY_OP + 1)
        c.epilogue()
    print(c.dump())
    return c.compile()


def compile_trace_c() -> peachpy.x86_64.function.ExecutableFuntion:  # [sic]
    """
    Compile the uops for `a = b + c`, assuming:
    * a: object
    * b: str
    * c: str
    """
    frame = peachpy.Argument(peachpy.ptr(), name="frame")
    with peachpy.x86_64.Function("<trace>", [frame], peachpy.int32_t) as trace:
        c = UopCompiler(trace)
        r_sum = peachpy.x86_64.GeneralPurposeRegister64()
        r_tmp = peachpy.x86_64.GeneralPurposeRegister64()
        c.prologue()
        c.UOP_JUMP(3)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_GUARD_UNICODE(c.localsplus(0))
        c.UOP_GUARD_UNICODE(c.localsplus(1))
        c.UOP_BINARY_OP_ADD_UNICODE(r_sum, c.localsplus(0), c.localsplus(1))
        c.UOP_ERROR_IF_NULL(r_sum)
        c.UOP_JUMP(INLINE_CACHE_ENTRIES_BINARY_OP + 1)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_GET_FAST(r_tmp, 2)
        c.UOP_STORE_FAST(2, r_sum)
        c.UOP_DECREF(r_tmp)
        c.epilogue()
    print(c.dump())
    return c.compile()


def compile_trace_d() -> peachpy.x86_64.function.ExecutableFuntion:  # [sic]
    """
    Compile the uops for `a = b + c`, assuming:
    * a: NULL
    * b: str
    * c: str
    """
    frame = peachpy.Argument(peachpy.ptr(), name="frame")
    with peachpy.x86_64.Function("<trace>", [frame], peachpy.int32_t) as trace:
        c = UopCompiler(trace)
        c.prologue()
        c.UOP_JUMP(3)
        c.UOP_WRITE_PREV_INSTR()
        c.UOP_GUARD_UNICODE(c.localsplus(0))
        c.UOP_GUARD_UNICODE(c.localsplus(1))
        c.UOP_BINARY_OP_ADD_UNICODE(c.localsplus(2), c.localsplus(0), c.localsplus(1))
        c.UOP_ERROR_IF_NULL(c.localsplus(2))
        c.UOP_JUMP(INLINE_CACHE_ENTRIES_BINARY_OP + 1)
        c.epilogue()
    print(c.dump())
    return c.compile()


class C:
    """An object that can be weakly referenced."""
    pass


def test_trace_a_success() -> None:
    b = "Hello, "
    c = "world!"
    a = C()
    a_ref = weakref.ref(a)
    trace = compile_trace_a()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 1
    assert a == "Hello, world!"
    assert b == "Hello, "
    assert c == "world!"
    assert a_ref() is None


def test_trace_a_error() -> None:
    b = "Hello, "
    c = 42
    a = C()
    a_ref = weakref.ref(a)
    trace = compile_trace_a()
    frame = get_interpreter_frame()
    with pytest.raises(TypeError):
        trace(frame)
    assert a is a_ref()
    assert b == "Hello, "
    assert c == 42


def test_trace_b_success() -> None:
    b = "Hello, "
    c = "world!"
    a = None
    del a
    trace = compile_trace_b()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 1
    assert a == "Hello, world!"  # type: ignore
    assert b == "Hello, "
    assert c == "world!"


def test_trace_b_error() -> None:
    b = "Hello, "
    c = 42
    a = None
    del a
    trace = compile_trace_b()
    frame = get_interpreter_frame()
    with pytest.raises(TypeError):
        trace(frame)
    with pytest.raises(UnboundLocalError):
        a  # type: ignore
    assert b == "Hello, "
    assert c == 42


def test_trace_c_success() -> None:
    b = "Hello, "
    c = "world!"
    a = C()
    a_ref = weakref.ref(a)
    trace = compile_trace_c()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 1
    assert a == "Hello, world!"
    assert b == "Hello, "
    assert c == "world!"
    assert a_ref() is None


def test_trace_c_deopt() -> None:
    b = "Hello, "
    c = 42
    a = C()
    a_ref = weakref.ref(a)
    trace = compile_trace_c()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 0
    assert a == a_ref()
    assert b == "Hello, "
    assert c == 42


def test_trace_d_success() -> None:
    b = "Hello, "
    c = "world!"
    a = None
    del a
    trace = compile_trace_d()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 1
    assert a == "Hello, world!"  # type: ignore
    assert b == "Hello, "
    assert c == "world!"


def test_trace_d_deopt() -> None:
    b = "Hello, "
    c = 42
    a = None
    del a
    trace = compile_trace_d()
    frame = get_interpreter_frame()
    trace_return = trace(frame)
    assert trace_return == 0
    with pytest.raises(UnboundLocalError):
        a  # type: ignore
    assert b == "Hello, "
    assert c == 42
