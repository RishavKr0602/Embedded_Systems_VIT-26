"""Regression tests for the two-Raspberry-Pi secure channel.

This package marker makes ``unittest`` treat the repository root as the
top-level directory, so discovery works from any working directory:

    python -m unittest discover -s Validation -p 'Test_*.py'

Without it, ``unittest`` sets the top-level directory to ``Validation/`` and
imports the test modules as top-level modules, so ``import ECC_Integration``
and ``import pi_node`` only resolve when the current directory happens to be
the repository root.
"""
