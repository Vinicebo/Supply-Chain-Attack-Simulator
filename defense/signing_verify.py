"""
Defense #5 -- Package signing & signature verification.

If publishers sign their artifacts and installers verify the signature against a
TRUSTED public key, a package produced by anyone else (the attacker) fails
verification even if the name and version match. This is the model behind
Sigstore, PEP 740 (PyPI attestations), and GPG-signed releases.

We implement a small, transparent signing scheme:
  * Ed25519 via `cryptography` when available (real asymmetric signatures), or
  * an HMAC-SHA256 fallback (symmetric, for environments without cryptography)
    -- clearly labelled as a demo stand-in.

Flow:
    keygen        -> creates a publisher keypair (trusted_key.pub / signing_key)
    sign <art>    -> writes <art>.sig using the signing key
    verify <art>  -> checks <art>.sig against the trusted public key

The attack demo signs the LEGIT artifact with the trusted key, then shows the
MALICIOUS artifact failing verification because it was never signed by that key.

Usage:
    python -m defense.signing_verify keygen
    python -m defense.signing_verify sign  <artifact>
    python -m defense.signing_verify verify <artifact>
    python -m defense.signing_verify explain
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import scas_config  # noqa: E402,F401  (imported for its UTF-8 console setup)

KEYDIR = REPO_ROOT / "artifacts" / "keys"
PRIV_PATH = KEYDIR / "signing_key"
PUB_PATH = KEYDIR / "trusted_key.pub"


def _have_crypto() -> bool:
    try:
        import cryptography  # noqa
        return True
    except Exception:
        return False


def _digest(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.digest()


# --------------------------------------------------------------------------- #
# Ed25519 backend (asymmetric -- the real thing)
# --------------------------------------------------------------------------- #
def _keygen_ed25519() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    KEYDIR.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    PRIV_PATH.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    PUB_PATH.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def _sign_ed25519(path: Path) -> dict:
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
    sig = priv.sign(_digest(path))
    return {"scheme": "ed25519", "sha256": _digest(path).hex(),
            "signature": base64.b64encode(sig).decode()}


def _verify_ed25519(path: Path, sigrec: dict) -> bool:
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    pub = serialization.load_pem_public_key(PUB_PATH.read_bytes())
    try:
        pub.verify(base64.b64decode(sigrec["signature"]), _digest(path))
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# HMAC backend (symmetric -- demo stand-in when cryptography is absent)
# --------------------------------------------------------------------------- #
def _keygen_hmac() -> None:
    import os
    KEYDIR.mkdir(parents=True, exist_ok=True)
    key = base64.b64encode(os.urandom(32)).decode()
    PRIV_PATH.write_text(key, encoding="utf-8")
    PUB_PATH.write_text(key, encoding="utf-8")  # symmetric: "public" == private


def _sign_hmac(path: Path) -> dict:
    key = PRIV_PATH.read_text(encoding="utf-8").strip().encode()
    mac = hmac.new(key, _digest(path), hashlib.sha256).hexdigest()
    return {"scheme": "hmac-sha256(demo)", "sha256": _digest(path).hex(),
            "signature": mac}


def _verify_hmac(path: Path, sigrec: dict) -> bool:
    key = PUB_PATH.read_text(encoding="utf-8").strip().encode()
    expected = hmac.new(key, _digest(path), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sigrec.get("signature", ""))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def keygen() -> int:
    if _have_crypto():
        _keygen_ed25519()
        print(f"✅ Generated Ed25519 keypair -> {PRIV_PATH.name}, {PUB_PATH.name}")
    else:
        _keygen_hmac()
        print("⚠️ cryptography not installed; generated an HMAC demo key instead.")
        print("   Install `cryptography` for real asymmetric Ed25519 signatures.")
    return 0


def sign(path: Path) -> int:
    if not PRIV_PATH.exists():
        print("No signing key. Run: python -m defense.signing_verify keygen")
        return 2
    rec = _sign_ed25519(path) if _have_crypto() else _sign_hmac(path)
    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    print(f"✅ Signed {path.name} ({rec['scheme']}) -> {sig_path.name}")
    return 0


def verify(path: Path) -> int:
    sig_path = path.with_suffix(path.suffix + ".sig")
    if not sig_path.exists():
        print(f"🚨 signing_verify: NO SIGNATURE for {path.name}.")
        print("    An unsigned artifact from an index that should only serve")
        print("    signed packages is rejected. This is how signing blocks a")
        print("    dependency-confusion artifact the attacker never signed.")
        return 1
    rec = json.loads(sig_path.read_text(encoding="utf-8"))
    ok = _verify_ed25519(path, rec) if _have_crypto() and rec["scheme"] == "ed25519" \
        else _verify_hmac(path, rec)
    if ok:
        print(f"✅ signing_verify: {path.name} signature is valid ({rec['scheme']}).")
        return 0
    print(f"🚨 signing_verify: INVALID signature for {path.name}.")
    print("    The artifact was not signed by the trusted publisher key.")
    return 1


_EXPLAIN = """
Package signing -- real-world equivalents
=========================================

PyPI attestations (PEP 740) + Sigstore:
  * CI signs each artifact with a short-lived Sigstore identity tied to your
    repo, and PyPI stores the attestation. Consumers verify the artifact was
    built by YOUR repo's workflow -- not an attacker.
    Publish:  uses `pypa/gh-action-pypi-publish` with `attestations: true`.

GPG-signed releases:
  * Publisher signs the sdist/wheel; consumers verify against a trusted key.

Why it blocks dependency confusion:
  * The attacker can match your name and version, but cannot produce a
    signature that verifies against your trusted key or a Sigstore identity
    bound to your repository. Verification fails; the install is refused.
Caveat: signing only helps if consumers actually REQUIRE and verify signatures.
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Package signing & verification.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    s = sub.add_parser("sign"); s.add_argument("artifact")
    v = sub.add_parser("verify"); v.add_argument("artifact")
    sub.add_parser("explain")
    args = p.parse_args(argv)

    if args.cmd == "keygen":
        return keygen()
    if args.cmd == "sign":
        return sign(Path(args.artifact))
    if args.cmd == "verify":
        return verify(Path(args.artifact))
    if args.cmd == "explain":
        print(_EXPLAIN); return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
