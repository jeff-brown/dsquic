"""Scaffold integrity checks.

Every module under dsquic must import cleanly, carry an RFC-mapping
docstring, and have a mirror file under tests/.
"""

import importlib
import pkgutil
from pathlib import Path

import pytest

import dsquic

MODULE_NAMES = sorted(module.name for module in pkgutil.iter_modules(dsquic.__path__))

TESTS_DIR = Path(__file__).parent


def test_scaffold_is_nonempty() -> None:
    assert MODULE_NAMES, "no modules found under dsquic"


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_module_imports_and_is_documented(name: str) -> None:
    module = importlib.import_module(f"dsquic.{name}")
    assert module.__doc__, f"dsquic.{name} is missing its RFC-mapping docstring"


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_module_has_test_file(name: str) -> None:
    assert (TESTS_DIR / f"test_{name}.py").is_file(), (
        f"dsquic.{name} has no tests/test_{name}.py mirror"
    )
