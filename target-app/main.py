"""
Target FastAPI application (the victim).

This is an ordinary-looking service. It loads config from a `.env` file (fake
credentials, for realism) and imports `internal_auth_utils` -- the package an
attacker can hijack via dependency confusion.

The vulnerability is NOT in this code. It is in how the app's dependencies are
*resolved and installed*. By the time this file runs, the damage (arbitrary
code execution during `uv sync`) has already occurred.
"""
import os

from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

app = FastAPI(title="Target App", version="0.1.0")

# These are FAKE and exist only to make the demo realistic. A real payload
# that DID read secrets would find values like these. Ours never touches them.
DB_URL = os.environ.get("DATABASE_URL", "not-set")
API_KEY = os.environ.get("THIRD_PARTY_API_KEY", "not-set")


@app.get("/")
def index():
    # Import here so the app still boots even if the dependency is absent.
    try:
        import internal_auth_utils

        auth_banner = internal_auth_utils.BANNER
        auth_version = internal_auth_utils.__version__
    except Exception as exc:  # pragma: no cover
        auth_banner = f"internal_auth_utils not importable: {exc}"
        auth_version = "unknown"

    return {
        "service": "target-app",
        "internal_auth_utils_version": auth_version,
        "internal_auth_utils_banner": auth_banner,
        # If the version is 99.0.0 you were served the MALICIOUS package.
        "compromised_hint": auth_version == "99.0.0",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
