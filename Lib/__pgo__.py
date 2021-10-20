import functools
import subprocess
import tempfile
import pathlib
import venv
import sys


PIP_COMMANDS = [
    ["install", "pyperformance"],
]
PYPERFORMANCE_COMMANDS = [
    ["venv", "recreate", "--python", sys.executable],
    ["run", "--fast"],
]

run = functools.partial(subprocess.run, check=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as temp:
        work = pathlib.Path(temp)
        venv.create(work / "pgo", clear=True, with_pip=True)
        pip = work / "pgo" / "bin" / "pip"
        for command in PIP_COMMANDS:
            run([pip, *command])
        pyperformance = work / "pgo" / "bin" / "pyperformance"
        for command in PYPERFORMANCE_COMMANDS:
            run([pyperformance, *command, "--venv", work / "bench"])


if __name__ == "__main__":
    main()
