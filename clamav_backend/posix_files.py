"""File operations anchored to open directory descriptors on POSIX."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import secrets
import shutil
import stat
from typing import BinaryIO


@contextmanager
def directory(path: str, *, create: bool = False):
    """Open each component without following symlinks and retain the final descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in os.path.abspath(path).split("/"):
            if not part:
                continue
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=fd)
            except NotADirectoryError as exc:
                raise PermissionError(f"Directory component is not a real directory: {part}") from exc
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def locked_quarantine(fd: int):
    """Serialize quarantine changes across helper processes."""
    import fcntl

    lock = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise PermissionError("Quarantine lock must be a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock)


@contextmanager
def regular_file(directory_fd: int, name: str):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError(f"Expected a regular file: {name}")
        yield stream, info


def read_manifest(directory_fd: int, name: str) -> dict:
    try:
        with regular_file(directory_fd, name) as (stream, _):
            value = json.load(stream)
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Invalid quarantine manifest")
    return value


def write_manifest(directory_fd: int, name: str, value: dict) -> None:
    temp_name = f".manifest-{secrets.token_hex(12)}"
    fd = os.open(temp_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    except BaseException:
        os.unlink(temp_name, dir_fd=directory_fd)
        raise


def same_entry(directory_fd: int, name: str, info: os.stat_result) -> bool:
    try:
        return os.path.samestat(info, os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return False


def copy_exclusive(
    source: BinaryIO,
    directory_fd: int,
    name: str,
    mode: int,
    ownership: tuple[int, int] | None = None,
) -> os.stat_result:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "wb") as output:
        info = os.fstat(output.fileno())
        try:
            shutil.copyfileobj(source, output)
            output.flush()
            if ownership is not None:
                os.fchown(output.fileno(), *ownership)
            os.fchmod(output.fileno(), mode & 0o777)
            os.fsync(output.fileno())
            if not same_entry(directory_fd, name, info):
                raise PermissionError(f"Destination changed during copy: {name}")
        except BaseException:
            if same_entry(directory_fd, name, info):
                os.unlink(name, dir_fd=directory_fd)
            raise
    return info
