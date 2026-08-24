"""Secure, atomic helpers for files containing assessment data."""

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, TextIO, Union
from collections.abc import Iterator


PathLike = Union[str, os.PathLike]


@contextmanager
def atomic_text_writer(
    output_path: PathLike,
    *,
    encoding: str = "utf-8",
    newline: Optional[str] = None,
    mode: int = 0o600,
) -> Iterator[TextIO]:
    """Yield a private temporary text file and atomically replace the target."""
    target = Path(output_path)
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {parent}")

    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=parent,
    )
    try:
        os.fchmod(file_descriptor, mode)
        with os.fdopen(
            file_descriptor,
            "w",
            encoding=encoding,
            newline=newline,
        ) as file_handle:
            yield file_handle
            file_handle.flush()
            os.fsync(file_handle.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def atomic_write_text(
    output_path: PathLike,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> None:
    """Write text privately and atomically to an output path."""
    with atomic_text_writer(output_path, encoding=encoding, mode=mode) as file_handle:
        file_handle.write(content)
