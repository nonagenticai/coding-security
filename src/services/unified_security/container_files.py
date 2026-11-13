"""Container source-file resolution helpers for unified security scanning.

Free-function helpers used by source-specific scanners to discover source
files, dependency lockfiles, and Python requirements files inside a
container path.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def resolve_container_files(container_name: str) -> list[str]:
    """Resolve source files in container.

    Args:
        container_name: Container name/path

    Returns:
        List of source file paths
    """
    try:
        container_path = Path(container_name)

        if not container_path.exists():
            logger.warning(f"Container path not found: {container_name}")
            return []

        extensions = [
            ".py",
            ".java",
            ".js",
            ".ts",
            ".go",
            ".rs",
            ".cs",
            ".cpp",
            ".c",
        ]
        files: list[Path] = []

        for ext in extensions:
            files.extend(container_path.glob(f"**/*{ext}"))

        return [str(f) for f in files if f.is_file()]

    except Exception as e:
        logger.warning(f"Error resolving container files: {e}")
        return []


async def find_lockfiles(container_name: str) -> list[str]:
    """Find dependency lockfiles in container.

    Args:
        container_name: Container name/path

    Returns:
        List of lockfile paths
    """
    try:
        container_path = Path(container_name)

        if not container_path.exists():
            return []

        lockfile_names = [
            "package-lock.json",
            "requirements.txt",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "pom.xml",
        ]

        lockfiles: list[str] = []
        for filename in lockfile_names:
            matching = list(container_path.glob(f"**/{filename}"))
            lockfiles.extend([str(f) for f in matching if f.is_file()])

        return lockfiles

    except Exception as e:
        logger.warning(f"Error finding lockfiles: {e}")
        return []


async def find_requirements_files(container_name: str) -> list[str]:
    """Find Python requirements files in container.

    Args:
        container_name: Container name/path

    Returns:
        List of requirements file paths
    """
    try:
        container_path = Path(container_name)

        if not container_path.exists():
            return []

        req_names = ["requirements.txt", "requirements-*.txt"]
        files: list[str] = []

        for pattern in req_names:
            matching = list(container_path.glob(f"**/{pattern}"))
            files.extend([str(f) for f in matching if f.is_file()])

        return files

    except Exception as e:
        logger.warning(f"Error finding requirements files: {e}")
        return []
