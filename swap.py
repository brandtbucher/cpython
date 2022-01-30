import itertools
import typing

# import tqdm

def do_swaps(swaps: typing.Sequence[int]) -> list[int]:
    depth = max(swaps, default=0)
    effect = list(range(depth))
    for swap in swaps:
        effect[0], effect[swap - 1] = effect[swap - 1], effect[0]
    while effect and effect[-1] == len(effect) - 1:
        del effect[-1]
    return effect

def assert_success(swaps: typing.Sequence[int], out: typing.Sequence[int]) -> None:
    effect = do_swaps(swaps)
    out_effect = do_swaps(out)
    assert out_effect == effect, (out, out_effect, swaps, effect)
    assert len(out) <= len(swaps), (out, out_effect, swaps, effect)

def swaptimize(swaps: tuple[int, ...]) -> list[int]:
    depth = max(swaps, default=0)
    effect = list(range(depth))
    for swap in swaps:
        top = effect[0]
        effect[0] = effect[swap - 1]
        effect[swap - 1] = top
    out = list(swaps)
    i = len(out)
    for start, x in enumerate(effect):
        if x < 0:
            continue
        j = i
        n = 0
        edge = start
        while 0 <= effect[edge]:
            if edge:
                j -= 1
                out[j] = edge + 1
            n += 1
            new = effect[edge]
            effect[edge] = -1
            edge = new
        if start:
            j -= 1
            out[j] = start + 1
        if 1 < n:
            i = j
        if i == 0:
            break
    del out[:i]
    assert_success(swaps, out)
    return out

def swaptimize(swaps: tuple[int, ...]) -> list[int]:
    depth = max(swaps, default=0)
    effect = list(range(depth))
    for swap in swaps:
        top = effect[0]
        effect[0] = effect[swap - 1]
        effect[swap - 1] = top
    out = list(swaps)
    i = len(out)
    for start, x in enumerate(effect):
        if x < 0:
            continue
        j = i
        n = 0
        edge = start
        assert 0 <= effect[edge]
        while 0 <= effect[edge]:
            if edge:
                j -= 1
                out[j] = edge + 1
            n += 1
            new = effect[edge]
            effect[edge] = -1
            edge = new
        if start:
            j -= 1
            out[j] = start + 1
        if 1 < n:
            i = j
        if i == 0:
            break
    del out[:i]
    assert_success(swaps, out)
    return out


def test_swaptimize() -> None:
    width = 1
    while True:
        depths = range(2, width + 2)
        examples = itertools.product(depths, repeat=width)
        total = len(depths) ** width
        for example in tqdm.tqdm(examples, total=total, unit_scale=True):
            swaptimize(example)
        width += 1

if __name__ == "__main__":
    test_swaptimize()