"""Scaffold integrity checks.

Every module under dsquic must import cleanly and carry a docstring.
Every non-package module must have a mirror test file:
tests/test_<name>.py, or tests/<subpackage>/test_<name>.py for
subpackage modules.

h3.py and qpack.py additionally import nothing of ours but buffer, so
that publishing either as a separate artifact stays possible without a
refactor (design.md appendix).
"""

import ast
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


# design.md appendix: HTTP/3 and QPACK are written to be liftable out of
# this package, so their only dsquic dependency is the varint codec of
# RFC 9000 §16. The transport reaches them through a typing.Protocol and
# arriving data through method calls, neither of which is an import.
PORTABLE_MODULES = ("h3", "qpack")
PORTABLE_IMPORTS = {"dsquic.buffer"}

SOURCE_DIR = Path(__file__).parent.parent / "src" / "dsquic"


def _dsquic_imports(path: Path) -> set[str]:
    """Every dsquic module a source file imports, by dotted name."""
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names if alias.name.startswith("dsquic"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "dsquic":
                found.update(f"dsquic.{alias.name}" for alias in node.names)
            elif node.module.startswith("dsquic"):
                found.add(node.module)
    return found


@pytest.mark.parametrize("name", PORTABLE_MODULES)
def test_portable_modules_depend_only_on_varints(name: str) -> None:
    """Keeps h3.py and qpack.py liftable.

    An import of connection.py or packet.py here would tie HTTP/3 to this
    QUIC implementation, which is the entanglement design.md §3 records
    every other Python HTTP/3 stack as having.
    """
    imports = _dsquic_imports(SOURCE_DIR / f"{name}.py")
    assert imports <= PORTABLE_IMPORTS, (
        f"{name}.py imports {sorted(imports - PORTABLE_IMPORTS)}; "
        f"only {sorted(PORTABLE_IMPORTS)} keeps it publishable on its own"
    )
