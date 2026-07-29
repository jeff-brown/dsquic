"""The shape of the PEM credential fixture, for typing interop peers.

Structural rather than an import, because the fixture itself lives in
the shared conftest, which pytest loads by path rather than by module.
"""

from pathlib import Path
from typing import Protocol


class PemCredentials(Protocol):
    ca_pem: Path
    certificate_pem: Path
    private_key_pem: Path
