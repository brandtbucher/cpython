import ast
import dataclasses


def compiler_expr(node: ast.expr) -> None:
    ...

def set_loc(node: ast.AST) -> None:
    ...


def emit(opcode: str, oparg: object = None) -> None:
    ...


@dataclasses.dataclass
class spm_subpattern:
    pattern: ast.pattern
    link: "spm_subpattern" | None
    reachable: bool


@dataclasses.dataclass
class spm_pattern:
    match_case: ast.match_case
    names: list[str]
    subpatterns: spm_subpattern
    block: object
    link: "spm_pattern" | None
    stacksize: int
    fail_pop: list
    group: bool


def spm_expand_or(link: spm_pattern | None) -> None:
    while link is not None:
        if isinstance(link.subpatterns.pattern, ast.MatchOr):
            last = True
            for alt in reversed(link.subpatterns.pattern.patterns[1:]):
                link.link = spm_pattern(
                    match_case=link.match_case,
                    names=link.names[:],
                    subpatterns=spm_subpattern(
                        pattern=alt,
                        link=link.subpatterns.link,
                        reachable=False,
                    ),
                    block=object(),
                    link=link.link,
                    stacksize=link.stacksize,
                    fail_pop=link.fail_pop if last else [],
                    group=True,
                )
                last = False
            link.subpatterns.pattern = link.subpatterns.pattern
            link.fail_pop = []
        else:
            link = link.link


def spm_combine(a: spm_pattern) -> None:
    while a.link is not None:
        b = a.link
        if (
            a.match_case is b.match_case
            and a.subpatterns is b.subpatterns
            and a.names == b.names
        ):
            a.link = b.link
        else:
            a = b

def spm_compile_as(link: spm_pattern) -> None:
    pattern = link.subpatterns.pattern
    assert isinstance(pattern, ast.MatchAs)
    if pattern.name in link.names:
        raise SyntaxError
    spm_helper_store(pattern.name)
    link.subpatterns.pattern = pattern.pattern
    link.group = False

def spm_compile_class(link: spm_pattern) -> None:
    ... # TODO

def spm_compile_mapping(link: spm_pattern) -> None:
    ... # TODO

def spm_compile_sequence(link: spm_pattern) -> None:
    ... # TODO

def spm_compile_singleton(link: spm_pattern) -> None:
    ... # TODO

def spm_compile_star(link: spm_pattern) -> None:
    pattern = link.subpatterns.pattern
    assert isinstance(pattern, ast.MatchAs)
    if pattern.name in link.names:
        raise SyntaxError
    spm_helper_store(pattern.name)
    link.group = False

def spm_compile_value(link: spm_pattern) -> None:
    ... # TODO

def spm_compile(link: spm_pattern) -> None:
    sub = link.subpatterns
    while sub is not None:
        set_loc(sub.pattern)
        if isinstance(sub.pattern, ast.MatchAs):
            spm_compile_as(link)
        elif isinstance(sub.pattern, ast.MatchClass):
            spm_compile_class(link)
        elif isinstance(sub.pattern, ast.MatchMapping):
            spm_compile_mapping(link)
        elif isinstance(sub.pattern, ast.MatchOr):
            assert False
        elif isinstance(sub.pattern, ast.MatchSequence):
            spm_compile_sequence(link)
        elif isinstance(sub.pattern, ast.MatchSingleton):
            spm_compile_singleton(link)
        elif isinstance(sub.pattern, ast.MatchStar):
            spm_compile_star(link)
        elif isinstance(sub.pattern, ast.MatchValue):
            spm_compile_value(link)
        else:
            assert False

def compiler_match(node: ast.Match) -> None:
    compiler_expr(node.subject)
    matrix = None
    for case in reversed(node.cases):
        matrix = spm_pattern(
            match_case=case,
            names=[],
            subpatterns=spm_subpattern(
                pattern=case.pattern,
                link=None,
                reachable=False,
            ),
            block=object(),
            link=matrix,
            stacksize=1,
            fail_pop=[],
            group=True,
        )
    assert matrix is not None
    while True:
        spm_expand_or(matrix)
        spm_compile(matrix)
        spm_combine(matrix)
    # TODO: Finalize matrix by combining the remaining incompatible ors, linking
    # all of the blocks, and raising for unreachables!
