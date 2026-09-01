"""Benchmark package.

Present so the benchmark modules can share helpers via relative imports; without
it, ``tests/benchmarks/conftest.py`` would collide with ``tests/conftest.py`` on
the module name ``conftest``.
"""
