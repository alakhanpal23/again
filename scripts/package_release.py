#!/usr/bin/env python3
"""Create a release archive with normalized metadata.

The compiled binary itself is not claimed to be bit-for-bit reproducible. This
only removes runner UID/GID, path, mode, gzip timestamp, and tar timestamp from
the packaging layer.
"""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import stat
import tarfile
import tempfile


MAX_BINARY_BYTES = 64 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    info = args.binary.lstat()
    if not stat.S_ISREG(info.st_mode) or args.binary.is_symlink():
        raise SystemExit("binary must be a regular non-symlink file")
    if info.st_size <= 0 or info.st_size > MAX_BINARY_BYTES:
        raise SystemExit("binary size is outside the release limit")
    if args.source_date_epoch < 0:
        raise SystemExit("source date epoch must be non-negative")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{args.output.name}.", dir=args.output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=args.source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT
                ) as archive:
                    member = tarfile.TarInfo("again")
                    member.size = info.st_size
                    member.mode = 0o755
                    member.uid = 0
                    member.gid = 0
                    member.uname = "root"
                    member.gname = "root"
                    member.mtime = args.source_date_epoch
                    with args.binary.open("rb") as binary:
                        archive.addfile(member, binary)
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
