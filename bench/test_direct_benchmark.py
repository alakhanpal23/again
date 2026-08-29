from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import direct_benchmark  # noqa: E402


class DirectBenchmarkTests(unittest.TestCase):
    def test_state_directory_is_private_under_restrictive_caller_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = pathlib.Path(temporary) / "state"
            previous_umask = os.umask(0o777)
            try:
                direct_benchmark.create_private_state_directory(state)
            finally:
                os.umask(previous_umask)

            mode = stat.S_IMODE(state.stat().st_mode)
            self.assertEqual(mode, 0o700)


if __name__ == "__main__":
    unittest.main()
