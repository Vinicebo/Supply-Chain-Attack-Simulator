# target-app (the victim)

A small FastAPI service that depends on `internal-auth-utils`. It is the victim
in the dependency-confusion scenario.

## What happens during `uv sync`

1. `uv` reads `pyproject.toml` and sees the dependency `internal-auth-utils`.
2. It queries the configured indexes for available versions:
   - the **local private** index (`http://127.0.0.1:8080/simple/`), and
   - **public PyPI** (`https://pypi.org/simple/`).
3. Because `pyproject.toml` sets `index-strategy = "unsafe-best-match"`, uv
   collects versions from **every** index and picks the **highest** compatible
   one. The malicious package advertises `99.0.0`; any real internal build is
   lower (e.g. `1.4.2`). **`99.0.0` wins.**
4. `uv` downloads and **installs** the winning package. With an sdist, install
   runs the package's build/`setup.py`, which triggers the **hook**.
5. The hook collects host metadata and beacons it to the local monitor. The
   developer sees a normal, successful `uv sync`.

> **How the offline simulator maps to this:** the demo runner does not run
> `uv sync` here — it installs `internal-auth-utils` straight from the local
> registry (`--index-url http://127.0.0.1:8080/simple/`) so nothing touches the
> real internet. The `[[tool.uv.index]]` block above shows the *real-world*
> two-index config an attacker exploits; the resolution logic is identical.

## Run the app

The app depends on `internal-auth-utils`, so the **local registry must be
running** (and the package published) before you start it:

```bash
python ../runner/demo.py build       # publish the package to the local registry
python ../runner/demo.py registry    # in another terminal: start the registry
```

Then, from this directory:

```bash
uv run --index-url http://127.0.0.1:8080/simple/ uvicorn main:app --reload --port 8000
```

Open <http://127.0.0.1:8000/> — if `internal_auth_utils_version` is `99.0.0`,
you were served the malicious package (`compromised_hint` will be `true`).
