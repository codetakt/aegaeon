from __future__ import annotations

import base64
import hashlib
import hmac
import json
import pathlib
import time
from typing import Any

import jwt
import yaml
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from jwcrypto import jwe, jwk

VECTORS_DIR = pathlib.Path(__file__).resolve().parent.parent / "vectors"
ARTIFACT_DIR = pathlib.Path(__file__).resolve().parents[2] / "artifacts" / "conformance"
MIN_PASS_RATE = 95.0


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def verify_jws(vec: dict[str, Any]) -> bool:
    alg = vec["alg"]
    if "expected_compact" in vec:
        header_b64, payload_b64, sig_b64 = vec["expected_compact"].split(".")
    elif "expected_flattened" in vec:
        data = vec["expected_flattened"]
        payload_b64 = data["payload"]
        header_b64 = data.get("protected", "")
        sig_b64 = data.get("signature", "")
    elif "expected_general" in vec:
        data = vec["expected_general"]
        payload_b64 = data["payload"]
        header_b64 = ""
        sig_b64 = ""
        # search for matching header/signature pair
        for sig in data.get("signatures", []):
            hb64 = sig.get("protected", "")
            sb64 = sig.get("signature", "")
            hdr = {}
            if hb64:
                hdr.update(json.loads(b64url_decode(hb64).decode()))
            hdr.update(sig.get("header", {}))
            if hdr == vec["header"]:
                header_b64 = hb64
                sig_b64 = sb64
                break
        if not header_b64:
            return False
    else:
        return False
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        if alg == "none":
            valid = sig_b64 == ""
        elif alg.startswith("HS"):
            key = b64url_decode(vec["key"])
            if alg == "HS256":
                expected = hmac.new(key, signing_input, hashlib.sha256).digest()
            elif alg == "HS384":
                expected = hmac.new(key, signing_input, hashlib.sha384).digest()
            elif alg == "HS512":
                expected = hmac.new(key, signing_input, hashlib.sha512).digest()
            else:
                return False
            valid = base64.urlsafe_b64encode(expected).decode().rstrip("=") == sig_b64
        else:
            token = f"{header_b64}.{payload_b64}.{sig_b64}"
            jwt.decode(
                token,
                vec["key"],
                algorithms=[alg],
                options={"verify_signature": True, "verify_exp": False},
            )
            valid = True
    except Exception:
        valid = False
    header = json.loads(b64url_decode(header_b64).decode()) if header_b64 else {}
    payload = json.loads(b64url_decode(payload_b64).decode())
    return valid and header == vec["header"] and payload == vec["payload"]


def verify_jwe(vec: dict[str, Any]) -> bool:
    token = vec["token"]
    try:
        header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = token.split(".")
    except ValueError:
        return False

    header = json.loads(b64url_decode(header_b64))
    if vec["enc"] == "C20P" and vec["alg"] == "dir":
        # jwcrypto currently rejects C20P; perform manual ChaCha20-Poly1305 verification.
        if encrypted_key_b64:
            return False
        key_bytes = b64url_decode(vec["key"])
        nonce = b64url_decode(iv_b64)
        ciphertext = b64url_decode(ciphertext_b64)
        tag = b64url_decode(tag_b64)
        aad = header_b64.encode()
        try:
            plaintext = ChaCha20Poly1305(key_bytes).decrypt(nonce, ciphertext + tag, aad)
        except Exception:
            return False
        try:
            payload = plaintext.decode()
        except UnicodeDecodeError:
            return False
        return (
            payload == vec["payload"]
            and header.get("alg") == vec["alg"]
            and header.get("enc") == vec["enc"]
        )

    key = jwk.JWK(kty="oct", k=vec["key"])
    j = jwe.JWE()
    try:
        j.deserialize(token, key)
        payload = j.payload.decode()
        header = j.jose_header
        return (
            payload == vec["payload"]
            and header.get("alg") == vec["alg"]
            and header.get("enc") == vec["enc"]
        )
    except Exception:
        return False


def verify_jwk(vec: dict[str, Any]) -> bool:
    try:
        key = jwk.JWK.from_json(json.dumps(vec["jwk"]))
        exported_json = key.export(private_key=True) if key.has_private else key.export()
        exported = json.loads(exported_json)
        return all(exported.get(k) == v for k, v in vec["jwk"].items())
    except Exception:
        return False


def _decode_segment(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    data = base64.urlsafe_b64decode(segment + padding)
    return json.loads(data.decode())


def verify_dpop(vec: dict[str, Any]) -> bool:
    proof = vec["proof"]
    try:
        header_b64, payload_b64, signature_b64 = proof.split(".")
    except ValueError:
        return False

    try:
        header = _decode_segment(header_b64)
        payload = _decode_segment(payload_b64)
    except (json.JSONDecodeError, ValueError, base64.binascii.Error):
        return False

    if header.get("typ") != "dpop+jwt":
        return False

    method = vec["method"]
    uri = vec["uri"]
    if payload.get("htm") != method or payload.get("htu") != uri:
        return False

    iat = payload.get("iat")
    if not isinstance(iat, int):
        return False
    now = int(vec.get("now", time.time()))
    window = int(vec.get("iat_window", 300))
    if abs(now - iat) > window:
        return False

    if "jti" not in payload:
        return False

    expected_ath = vec.get("expected_ath")
    actual_ath = payload.get("ath")
    if expected_ath is not None:
        if actual_ath != expected_ath:
            return False
    elif actual_ath is not None:
        return False

    # Conformance vectors intentionally omit signatures (alg=none)
    return signature_b64 in ("", None)


def main() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    logs = []
    total = passed = 0

    # JWS vectors (all jws*.yaml files)
    for file in sorted(VECTORS_DIR.glob("jws*.yaml")):
        vectors = yaml.safe_load(file.read_text())
        for vec in vectors:
            ok = verify_jws(vec)
            logs.append(f"JWS {file.name}: {vec['description']}: {'PASS' if ok else 'FAIL'}")
            passed += ok
            total += 1

    # JWE vectors (files ending with _vectors.yaml)
    for file in sorted(VECTORS_DIR.glob("jwe*_vectors.yaml")):
        vectors = yaml.safe_load(file.read_text())
        for vec in vectors:
            ok = verify_jwe(vec)
            logs.append(f"JWE {file.name}: {vec['description']}: {'PASS' if ok else 'FAIL'}")
            passed += ok
            total += 1

    # JWK vectors (all jwk*_vectors.json files)
    for file in sorted(VECTORS_DIR.glob("jwk*_vectors.json")):
        vectors = json.loads(file.read_text())
        for vec in vectors:
            ok = verify_jwk(vec)
            logs.append(f"JWK {file.name}: {vec['description']}: {'PASS' if ok else 'FAIL'}")
            passed += ok
            total += 1

    # DPoP vectors (all dpop*_vectors.yaml files)
    for file in sorted(VECTORS_DIR.glob("dpop*_vectors.yaml")):
        vectors = yaml.safe_load(file.read_text())
        for vec in vectors:
            proof_ok = verify_dpop(vec)
            expect = str(vec.get("expect", "pass")).lower() == "pass"
            ok = proof_ok == expect
            outcome = "valid" if proof_ok else "invalid"
            logs.append(
                f"DPoP {file.name}: {vec['description']}: {'PASS' if ok else 'FAIL'} "
                f"(evaluated {outcome})"
            )
            passed += ok
            total += 1

    pass_rate = (passed / total * 100) if total else 0.0
    ARTIFACT_DIR.joinpath("jose_vectors.log").write_text("\n".join(logs) + "\n")
    summary = {"total": total, "passed": passed, "pass_rate": pass_rate}
    ARTIFACT_DIR.joinpath("summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"pass rate: {pass_rate:.2f}% ({passed}/{total})")
    if pass_rate < MIN_PASS_RATE:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
