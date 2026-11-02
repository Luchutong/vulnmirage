"""Small cross-platform file lock used for repository cache mutation."""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import TracebackType

from .errors import RepositoryError


class FileLock:
    def __init__(self, path: Path, *, timeout: float = 300.0, stale_after: float = 3600.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.stale_after = stale_after
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age > self.stale_after:
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() > deadline:
                    raise RepositoryError(
                        f"timed out waiting for repository cache lock: {self.path}",
                        details={"lock": str(self.path), "timeout": self.timeout},
                    )
                time.sleep(0.1)
                continue
            except OSError as exc:
                raise RepositoryError(
                    f"cannot create lock file {self.path}: {exc}",
                    details={"lock": str(self.path)},
                    cause=exc,
                ) from exc
            self._fd = fd
            os.write(fd, f"{os.getpid()} {time.time()}\n".encode("ascii"))
            os.fsync(fd)
            return

    def release(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
