"""
internal-auth-utils (DEMONSTRATION PACKAGE)

In a real dependency-confusion attack the malicious package often ships a
plausible-looking module so the victim application keeps working and nobody
notices anything is wrong. This module mimics that: it exposes a tiny, benign
"auth utils" API surface that a target app might import.

The dangerous part already happened at INSTALL time (see setup.py). By the
time this module is imported, the post-install beacon has already fired.
"""

__version__ = "99.0.0"
__all__ = ["get_token", "verify", "BANNER"]

BANNER = (
    "internal-auth-utils v99.0.0 -- EDUCATIONAL dependency-confusion demo. "
    "The malicious behavior runs at install time, not import time."
)


def get_token(user: str = "service-account") -> str:
    """Return a fake token so the target app's code path stays functional."""
    return f"demo-token-for-{user}-do-not-use"


def verify(token: str) -> bool:
    """Pretend to verify a token. Always True in the demo."""
    return bool(token)
