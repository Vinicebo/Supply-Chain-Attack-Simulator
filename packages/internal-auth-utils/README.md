# internal-auth-utils (demonstration package)

> ⚠️ **Educational artifact.** This package deliberately reproduces a
> dependency-confusion payload for defensive training. It is safe by
> construction: loopback-only beacon, non-sensitive metadata, never published
> to a real registry.

## What it demonstrates

An attacker who learns the *name* of a company's private package (here,
`internal-auth-utils`) can publish a package with the **same name** and a
**higher version number** to a public index. When a developer's installer is
configured to search both the private and public indexes, it may pick the
attacker's higher-versioned public package instead of the real internal one —
**dependency confusion**.

The moment the package installs, `setup.py`'s post-install hook runs arbitrary
code. Ours only:

- collects hostname, username, Python version, platform, cwd, and a sample of
  installed package **names**, and
- POSTs that JSON to the local monitor at `http://127.0.0.1:8090/beacon`.

It never touches secrets, files, environment variables, or the internet.

## Why version `99.0.0`

Package managers resolve to the highest compatible version. `99.0.0` beats any
realistic internal version (e.g. `1.4.2`), so the malicious public package wins
resolution. This is the crux of the attack.

## Build & publish (to the LOCAL registry only)

Use the project runner (`python runner/demo.py ...`) or the scripts in
`scripts/`. Do **not** run `twine upload` against PyPI.
