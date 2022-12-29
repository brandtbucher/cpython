from dataclasses import dataclass

import pyperf


def bench_dataclass_1(count: int) -> float:
    loops = range(count)
    # Begin benchmark:
    start = pyperf.perf_counter()
    for _ in loops:
        @dataclass
        class Point:
            a: int
    return pyperf.perf_counter() - start

def bench_dataclass_2(count: int) -> float:
    loops = range(count)
    # Begin benchmark:
    start = pyperf.perf_counter()
    for _ in loops:
        @dataclass
        class Point:
            a: int
            b: int
    return pyperf.perf_counter() - start

def bench_dataclass_4(count: int) -> float:
    loops = range(count)
    # Begin benchmark:
    start = pyperf.perf_counter()
    for _ in loops:
        @dataclass
        class Point:
            a: int
            b: int
            c: int
            d: int
    return pyperf.perf_counter() - start

def bench_dataclass_8(count: int) -> float:
    loops = range(count)
    # Begin benchmark:
    start = pyperf.perf_counter()
    for _ in loops:
        @dataclass
        class Point:
            a: int
            b: int
            c: int
            d: int
            e: int
            f: int
            g: int
            h: int
    return pyperf.perf_counter() - start
        


if __name__ == "__main__":
    runner = pyperf.Runner()
    runner.metadata["description"] = "dataclasses"
    runner.bench_time_func("dataclass_1", bench_dataclass_1)
    runner.bench_time_func("dataclass_2", bench_dataclass_2)
    runner.bench_time_func("dataclass_4", bench_dataclass_4)
    runner.bench_time_func("dataclass_8", bench_dataclass_8)