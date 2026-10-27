"""Safe output writing."""
import os
import tempfile
from pathlib import Path


def publish(data: bytes, dest: Path) -> None:
    """Create dest with data, never overwriting (FileExistsError) and never leaving a partial file.

    Writes a temp file and hard-links it into place; on filesystems without hard links
    (FAT/exFAT, some network mounts) falls back to an exclusive create.
    """
    dest = Path(dest)
    umask = os.umask(0); os.umask(umask)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".icegate-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o666 & ~umask)  # mkstemp creates 0600
        try:
            os.link(tmp, dest)
        except FileExistsError:
            raise
        except OSError:
            fd2 = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
            try:
                with os.fdopen(fd2, "wb") as out:
                    out.write(data)
            except BaseException:
                os.unlink(dest)  # never leave a half-written output
                raise
    finally:
        os.unlink(tmp)
