#!/usr/bin/env python3
"""The device-certificate vectors are the bytes the format says, rebuilt here from the prose.

`knst_device_certificate.json` fixes what an account's device signs when it vouches for a newly
linked one, the certificate that carries the signature, and the Flow A proof of keys. construct-core
signs and verifies; this rebuilds the device ids, the QR fingerprint, the signed message, the
certificate layout and the HMAC with nothing but the standard library, so the file cannot drift
from construct-docs/decisions/devices-of-an-account-sign-each-other.md without something
reddening. Signatures (Ed25519, hybrid Ed25519 ‖ ML-DSA-65) are not checked here — that needs
those implementations; their lengths are.

Exit 1 on any disagreement. Run it from anywhere.
"""

import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parent / "knst_device_certificate.json"
HYBRID_PUBLIC_LEN = 32 + 1952
SIGNATURE_LEN = 64 + 3309
CERT_LEN = 1 + 16 + 8 + HYBRID_PUBLIC_LEN + SIGNATURE_LEN


def device_id(identity: bytes) -> bytes:
    return hashlib.sha256(identity).digest()[:16]


def fingerprint(identity: bytes, hybrid: bytes) -> bytes:
    return hashlib.sha256(identity + hybrid).digest()


def main() -> int:
    v = json.loads(VECTORS.read_text())
    errors = []

    def check(cond, what):
        if not cond:
            errors.append(what)

    keys = {}
    for role in ("signer", "subject"):
        k = {f: bytes.fromhex(v[role][f]) for f in ("identity", "verifying", "hybrid", "hybrid_binding")}
        check(len(k["identity"]) == 32, f"{role}: identity is 32 bytes")
        check(len(k["verifying"]) == 32, f"{role}: verifying key is 32 bytes")
        check(len(k["hybrid"]) == HYBRID_PUBLIC_LEN, f"{role}: hybrid public is {HYBRID_PUBLIC_LEN} bytes")
        check(len(k["hybrid_binding"]) == 64, f"{role}: hybrid binding is an Ed25519 signature")
        check(device_id(k["identity"]).hex() == v[role]["device_id"], f"{role}: device id")
        keys[role] = k

    signer, subject = keys["signer"], keys["subject"]
    message = (b"KonstruktDeviceCert-v1" + b"\x00"
               + device_id(signer["identity"]) + device_id(subject["identity"])
               + subject["identity"] + subject["verifying"] + subject["hybrid"]
               + struct.pack(">Q", v["issued_at"]))
    check(hashlib.sha256(message).hexdigest() == v["message_sha256"], "signed message")

    cert = bytes.fromhex(v["certificate"])
    check(len(cert) == CERT_LEN, f"certificate is {CERT_LEN} bytes")
    check(hashlib.sha256(cert).hexdigest() == v["certificate_sha256"], "certificate sha256")
    check(cert[0] == 1, "certificate version 1")
    check(cert[1:17] == device_id(signer["identity"]), "certificate names the signer")
    check(struct.unpack(">Q", cert[17:25])[0] == v["issued_at"], "certificate issued_at")
    check(cert[25:25 + HYBRID_PUBLIC_LEN] == signer["hybrid"], "certificate carries the signer's hybrid key")
    check(len(cert[25 + HYBRID_PUBLIC_LEN:]) == SIGNATURE_LEN, "certificate signature length")

    proof = hmac.new(bytes.fromhex(v["link_secret"]),
                     b"KonstruktLinkProof-v1" + b"\x00" + fingerprint(subject["identity"], subject["hybrid"]),
                     hashlib.sha256).hexdigest()
    check(proof == v["link_key_proof"], "Flow A link key proof")

    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    if not errors:
        print("device certificate vectors: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
