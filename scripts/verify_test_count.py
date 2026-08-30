from __future__ import annotations

import sys
import unittest

MINIMUM = 75

suite = unittest.defaultTestLoader.discover("tests")
count = suite.countTestCases()
print(f"discovered tests: {count}")
if count < MINIMUM:
    print(f"expected at least {MINIMUM} tests", file=sys.stderr)
    raise SystemExit(1)
