#!/usr/bin/env python3.8

import argparse
import pprint
import sys
from typing import Set, Dict

from pegen.build import build_parser
from pegen.grammar import (
    Alt,
    Cut,
    Gather,
    Grammar,
    Group,
    Leaf,
    Lookahead,
    NamedItem,
    NameLeaf,
    NegativeLookahead,
    Opt,
    Repeat,
    Repeat0,
    Repeat1,
    Rhs,
    Rule,
    StringLeaf,
    PositiveLookahead,
)

argparser = argparse.ArgumentParser(
    prog="calculate_first_sets", description="Calculate the first sets of a grammar",
)
argparser.add_argument("grammar_file", help="The grammar file")


class FirstSetCalculator:
    def __init__(self, rules: Dict[str, Rule]) -> None:
        self.rules = rules
        for rule in rules.values():
            rule.nullable_visit(rules)
        self.first_sets: Dict[str, Set[str]] = dict()
        self.in_process: Set[str] = set()

    def calculate(self) -> Dict[str, Set[str]]:
        for name, rule in self.rules.items():
            self.visit(rule)
        return self.first_sets

    def visit(self, item) -> Set[str]:
        match item:
            case Alt():
                result: Set[str] = set()
                to_remove: Set[str] = set()
                for other in item.items:
                    new_terminals = self.visit(other)
                    if isinstance(other.item, NegativeLookahead):
                        to_remove |= new_terminals
                    result |= new_terminals
                    if to_remove:
                        result -= to_remove

                    # If the set of new terminals can start with the empty string,
                    # it means that the item is completelly nullable and we should
                    # also considering at least the next item in case the current
                    # one fails to parse.

                    if "" in new_terminals:
                        continue

                    if not isinstance(other.item, (Opt, NegativeLookahead, Repeat0)):
                        break

                # Do not allow the empty string to propagate.
                result.discard("")

                return result

            case Cut():
                return set()

            case Group():
                return self.visit(item.rhs)

            case NamedItem():
                return self.visit(item.item)

            case Lookahead() | Opt() | Gather() | Repeat():
                return self.visit(item.node)

            case NameLeaf(value=v) if v not in self.rules:
                return {item.value}

            case NameLeaf(value=v) if v not in self.first_sets:
                self.first_sets[item.value] = self.visit(self.rules[item.value])
                return self.first_sets[item.value]

            case NameLeaf(value=v) if v in self.in_process:
                return set()

            case NameLeaf(value=v):
                return self.first_sets[v]

            case StringLeaf():
                return {item.value}

            case Rhs():
                result: Set[str] = set()
                for alt in item.alts:
                    result |= self.visit(alt)
                return result

            case Rule(name=name) if name in self.in_process:
                return set()

            case Rule(name=name, rhs=rhs, nullable=nullable):
                if name not in self.first_sets:
                    self.in_process.add(name)
                    terminals = self.visit(rhs)
                    if nullable:
                        terminals.add("")
                    self.first_sets[name] = terminals
                    self.in_process.remove(name)
                return self.first_sets[name]

            case _:
                assert False, item


def main() -> None:
    args = argparser.parse_args()

    try:
        grammar, parser, tokenizer = build_parser(args.grammar_file)
    except Exception as err:
        print("ERROR: Failed to parse grammar file", file=sys.stderr)
        sys.exit(1)

    firs_sets = FirstSetCalculator(grammar.rules).calculate()
    pprint.pprint(firs_sets)


if __name__ == "__main__":
    main()
