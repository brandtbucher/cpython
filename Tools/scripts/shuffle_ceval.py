"""
Reorder the cases of _PyEval_EvalFrameDefault in-place. The order is random by
default, but other orders can be specified:

./python Tools/scripts/shuffle_ceval.py density
    Run the PGO test suite and reorder the instructions by frequency of
    execution divided by approximate case size (requires
    -DDYNAMIC_EXECUTION_PROFILE).

./python Tools/scripts/shuffle_ceval.py frequency
    Run the PGO test suite and reorder the instructions by frequency of
    execution (requires -DDYNAMIC_EXECUTION_PROFILE).

./python Tools/scripts/shuffle_ceval.py name
    Reorder the instructions alphabetically by name.

./python Tools/scripts/shuffle_ceval.py original
    Write the instructions back in the same order (useful for debugging).

./python Tools/scripts/shuffle_ceval.py random
    Randomly shuffle the instructions (this is the default).

./python Tools/scripts/shuffle_ceval.py size
    Reorder the instructions by approximate case size.

./python Tools/scripts/shuffle_ceval.py value
    Reorder the instructions by numeric opcode value.
"""

import argparse
import functools
import opcode
import pathlib
import random
import re
import sys
import test.libregrtest  # type: ignore [import]
import typing


HINT = "(run this script using the same CPython version that's being shuffled)"

PATH_CEVAL = pathlib.Path(__file__).parent.parent.parent / "Python" / "ceval.c"

RE_NAME = r"([A-Z_]+)"
RE_BODY = r"( {8}TARGET\s*\(\s*" + RE_NAME + r"\s*\)\s*\{(?s:.*?)\n {8}\}\s*\n+)"


class Op(typing.NamedTuple):
    name: str
    body: str


@functools.cache
def get_opmap_full() -> dict[str, int]:
    if not hasattr(opcode, "_specialized_instructions"):
        raise RuntimeError(f"requires CPython 3.11+ {HINT}")
    opmap = {}
    specialized_instructions = iter(
        opcode._specialized_instructions  # type: ignore [attr-defined]
    )
    name: str | None
    for i, name in enumerate(opcode.opname[1:], 1):
        assert isinstance(name, str), name
        if name.startswith("<"):
            name = next(specialized_instructions, None)
        if name is not None:
            opmap[name] = i
    return opmap


def get_opcode(op: Op) -> int:
    opcode = get_opmap_full().get(op.name)
    if opcode is None:
        raise RuntimeError(f"unknown opname {op.name!r} {HINT}")
    return opcode


def get_profile() -> list[int]:
    if not hasattr(sys, "getdxp"):
        raise RuntimeError("requires -DDYNAMIC_EXECUTION_PROFILE")
    sys_argv = sys.argv[:]
    try:
        sys.argv[1:] = ["--pgo"]
        test.libregrtest.main()
    except SystemExit:
        pass
    finally:
        sys.argv[:] = sys_argv
    profile: list[int] = sys.getdxp()  # type: ignore [attr-defined]
    if isinstance(profile[0], list):
        # DXPAIRS is turned on. Sum each sublist to get a "normal" profile:
        profile = list(map(sum, profile))
    return profile


def order_density(ops: list[Op]) -> None:
    profile = get_profile()
    ops.sort(key=lambda op: profile[get_opcode(op)] / len(op.body), reverse=True)


def order_frequency(ops: list[Op]) -> None:
    profile = get_profile()
    ops.sort(key=lambda op: profile[get_opcode(op)], reverse=True)


def order_name(ops: list[Op]) -> None:
    ops.sort(key=lambda op: op.name)


def order_original(ops: list[Op]) -> None:
    pass


def order_random(ops: list[Op]) -> None:
    random.shuffle(ops)


def order_size(ops: list[Op]) -> None:
    ops.sort(key=lambda op: len(op.body))


def order_value(ops: list[Op]) -> None:
    ops.sort(key=get_opcode)


ORDERS = {
    "density": order_density,
    "frequency": order_frequency,
    "name": order_name,
    "original": order_original,
    "random": order_random,
    "size": order_size,
    "value": order_value,
}


def main(*args: str) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("order", nargs="?", choices=ORDERS, default="random")
    parsed = parser.parse_args(args)
    header, *bodies, footer = re.split(RE_BODY, PATH_CEVAL.read_text())
    bodies.append("")
    ops = []
    groups = zip(  # type: ignore [call-overload]
        bodies[::3], bodies[1::3], bodies[2::3], strict=True
    )
    for body, name, empty in groups:
        assert re.match(RE_BODY, body) is not None, body
        assert re.match(RE_NAME, name) is not None, name
        ops.append(Op(name=name, body=body))
        assert empty == "", empty
    ORDERS[parsed.order](ops)
    parts = [header, *(op.body for op in ops), footer]
    PATH_CEVAL.write_text("".join(parts))


if __name__ == "__main__":
    main(*sys.argv[1:])
