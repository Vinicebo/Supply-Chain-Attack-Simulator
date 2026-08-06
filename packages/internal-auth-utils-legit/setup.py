"""
setup.py for the LEGITIMATE internal-auth-utils (version 1.4.2).

This is what the company's *real* private package looks like: same name, a
normal version number, and NO post-install hook. The defense demos publish
this to a scoped/private index to show that when resolution is routed
correctly, the benign package wins and no beacon fires.
"""
from setuptools import setup, find_packages

setup(
    name="internal-auth-utils",
    version="1.4.2",
    description="Legitimate internal auth helpers (benign, no install hook).",
    author="ACME Platform Team (simulated)",
    license="Proprietary",
    packages=find_packages(),
    python_requires=">=3.9",
)
