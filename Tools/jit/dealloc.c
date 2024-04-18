#include "Python.h"

__attribute__((preserve_most)) void
_JIT_ENTRY(PyObject *o)
{
    _Py_Dealloc(o);
}