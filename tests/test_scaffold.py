"""Scaffold integrity checks.

Every module under dsquic must import cleanly and carry a docstring.
Every non-package module must have a mirror test file:
tests/test_<name>.py, or tests/<subpackage>/test_<name>.py for
subpackage modules.
"""

import importlib
import pkgutil
from pathlib import Path

import pytest

import dsquic

_WALKED = sorted(
    (module.name, module.ispkg)
    for module in pkgutil.walk_packages(dsquic.__path__, prefix="dsquic.")
)
ALL_MODULES = [name for name, _ in _WALKED]
LEAF_MODULES = [name for name, ispkg in _WALKED if not ispkg]

TESTS_DIR = Path(__file__).parent


def _mirror(name: str) -> Path:
    *packages, module = name.split(".")[1:]
    return TESTS_DIR.joinpath(*packages, f"test_{module}.py")


def test_scaffold_is_nonempty() -> None:
    assert ALL_MODULES, "no modules found under dsquic"


@pytest.mark.parametrize("name", ALL_MODULES)
def test_module_imports_and_is_documented(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__doc__, f"{name} is missing its docstring"


@pytest.mark.parametrize("name", LEAF_MODULES)
def test_module_has_test_file(name: str) -> None:
    assert _mirror(name).is_file(), f"{name} has no mirror at {_mirror(name)}"
