import shutil
import subprocess
import pathlib
import venv
import sys


VENV = pathlib.Path("venv")

PIP = VENV / "pgo" / "bin" / "pip"
PYPERFORMANCE = VENV / "pgo" / "bin" / "pyperformance"


if __name__ == "__main__":
    try:
        venv.create(VENV / "pgo", clear=True, with_pip=True)
        subprocess.run([PIP, "install", "pyperformance"])
        subprocess.run([PYPERFORMANCE, "venv", "recreate", "--python", sys.executable])
        subprocess.run([PYPERFORMANCE, "run", "--fast"])
    finally:
        shutil.rmtree(VENV, ignore_errors=True)
