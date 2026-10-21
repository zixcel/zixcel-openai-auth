"""Check tracked paths without reading or exposing their contents."""

from pathlib import PurePosixPath
from collections.abc import Iterable

from .types import RepositoryPolicy

FORBIDDEN_ROOTS = frozenset({
    "registration", "state", ".local", ".state", ".data", "secrets", "credentials",
    "target", "node_modules", "dist", "build", "coverage", ".cache",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".nox", "htmlcov",
})
ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template"})


def check_tracked_paths(paths: Iterable[str], policy: RepositoryPolicy) -> None:
    """Fail closed on local data, generated artifacts and non-template environments."""
    for name in paths:
        if not name:
            continue
        parts = PurePosixPath(name).parts
        if parts[0] in {"src", "scripts"} and name.endswith((".js", ".mjs", ".cjs")):
            raise ValueError("First-party runtime/checks must use Rust or typed source: " + name)
        forbidden = parts[0] in FORBIDDEN_ROOTS
        forbidden |= "node_modules" in parts or "__pycache__" in parts
        forbidden |= name.endswith((".pyc", ".tsbuildinfo", ".tgz")) and (
            name not in policy.allowed_vendor_archives
        )
        forbidden |= len(parts) == 1 and name.endswith((
            ".tar.gz", ".zip", ".whl", ".crate", ".profraw", ".profdata",
        ))
        forbidden |= parts[0].startswith(".env") and parts[0] not in ENV_TEMPLATES
        if forbidden and name not in policy.allowed_source_files:
            raise ValueError("Excluded local data or generated artifact is tracked: " + name)
