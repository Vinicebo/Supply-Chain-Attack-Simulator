"""
internal-auth-utils (LEGITIMATE v1.4.2)

The real internal package. Benign, no install-time behavior. Imported by the
target app exactly the same way as the malicious one -- which is precisely why
the attack is so effective: the API surface is identical.
"""

__version__ = "1.4.2"
__all__ = ["get_token", "verify", "BANNER"]

BANNER = "internal-auth-utils v1.4.2 -- legitimate internal build."


def get_token(user: str = "service-account") -> str:
    return f"real-token-for-{user}"


def verify(token: str) -> bool:
    return bool(token)
