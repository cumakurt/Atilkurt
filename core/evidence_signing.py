"""Bounded JWS/PS256 evidence with caller-supplied trusted public keys."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from core.exceptions import ValidationError
from core.secure_file import atomic_write_text

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_ENVELOPE_BYTES = (MAX_DOCUMENT_BYTES * 4 + 2) // 3 + 16384
MAX_KEY_BYTES = 64 * 1024


def canonical_json(document: Any) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False, default=str
    ).encode("utf-8")


def read_json(path: str, limit: int = MAX_ENVELOPE_BYTES) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(limit + 1)
        if len(payload) > limit:
            raise ValidationError("Input document exceeds the size limit")
        document = json.loads(payload.decode("utf-8-sig"), parse_constant=_invalid_constant)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"Cannot read JSON document: {path}") from exc
    if not isinstance(document, dict):
        raise ValidationError("Input document must be a JSON object")
    return document


def _invalid_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON value: {value}")


def read_key(path: str):
    try:
        with Path(path).open("rb") as stream:
            material = stream.read(MAX_KEY_BYTES + 1)
        if len(material) > MAX_KEY_BYTES:
            raise ValueError("Key is too large")
        key = RSA.import_key(material)
        if not 2048 <= key.size_in_bits() <= 8192:
            raise ValueError("RSA keys must have 2048 to 8192 bits")
        return key
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise ValidationError("Cannot read a supported RSA key") from exc


def key_id(key) -> str:
    return hashlib.sha256(key.public_key().export_key(format="DER")).hexdigest()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: Any, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValidationError("Invalid signed-document encoding")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("Invalid signed-document encoding") from exc
    if len(raw) > limit or _encode(raw) != value:
        raise ValidationError("Signed-document field is oversized or non-canonical")
    return raw


def sign_document(document: dict[str, Any], private_key_path: str) -> dict[str, str]:
    key = read_key(private_key_path)
    if not key.has_private():
        raise ValidationError("Signing requires a private key")
    payload = canonical_json(document)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValidationError("Document exceeds the signing limit")
    protected = _encode(canonical_json({"alg": "PS256", "kid": key_id(key), "typ": "ATILKURT-EVIDENCE"}))
    encoded = _encode(payload)
    signature = pss.new(key, salt_bytes=32).sign(SHA256.new((protected + "." + encoded).encode("ascii")))
    return {"protected": protected, "payload": encoded, "signature": _encode(signature)}


def unwrap_document(
    document: dict[str, Any], trusted_keys: list[str] | None = None, require_signed: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not any(field in document for field in ("protected", "signature")):
        if require_signed:
            raise ValidationError("Unsigned evidence is not allowed")
        if len(canonical_json(document)) > MAX_DOCUMENT_BYTES:
            raise ValidationError("Document exceeds the evidence size limit")
        return document, {"status": "unsigned"}
    if set(document) != {"protected", "payload", "signature"}:
        raise ValidationError("Invalid signed-document envelope")
    try:
        header = json.loads(_decode(document["protected"], 4096))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Invalid signature header") from exc
    if (
        not isinstance(header, dict)
        or header.get("alg") != "PS256"
        or header.get("typ") != "ATILKURT-EVIDENCE"
        or set(header) != {"alg", "kid", "typ"}
    ):
        raise ValidationError("Unsupported signature algorithm or header")
    keys = [read_key(path).public_key() for path in trusted_keys or []]
    key = next((candidate for candidate in keys if key_id(candidate) == header.get("kid")), None)
    if key is None:
        raise ValidationError("Evidence signer is not in the supplied trusted-key list")
    payload = _decode(document["payload"], MAX_DOCUMENT_BYTES)
    signature = _decode(document["signature"], 1024)
    try:
        message = (document["protected"] + "." + document["payload"]).encode("ascii")
        pss.new(key, salt_bytes=32).verify(SHA256.new(message), signature)
        content = json.loads(payload, parse_constant=_invalid_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Evidence signature or payload is invalid") from exc
    if not isinstance(content, dict):
        raise ValidationError("Signed payload must be a JSON object")
    return content, {"status": "verified", "key_id": header["kid"], "algorithm": "PS256"}


def write_document(path: str, document: dict[str, Any], signing_key: str | None = None) -> None:
    payload = sign_document(document, signing_key) if signing_key else document
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str, allow_nan=False))


def generate_keys(private_path: str, public_path: str) -> str:
    private = Path(private_path)
    public = Path(public_path)
    if (
        private.resolve() == public.resolve()
        or private.exists()
        or public.exists()
        or private.is_symlink()
        or public.is_symlink()
    ):
        raise ValidationError("Key generation requires two distinct, unused output paths")
    key = RSA.generate(3072)
    # Exclusive creation prevents another process's key from being overwritten.
    import os

    created = []
    try:
        for path, material in ((private, key.export_key(pkcs=8)), (public, key.public_key().export_key())):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(material)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        for path in created:
            path.unlink(missing_ok=True)
        raise ValidationError("Cannot write signing keys to the requested paths") from exc
    return key_id(key)
