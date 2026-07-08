"""
virus_scan.py
--------------
Module 4 - Basic Virus Detection.

Calculates the SHA-256 hash of an executable file and compares it
against a local database of known-malicious hashes (signature-based
detection). This is intentionally simple/educational - it is NOT a
replacement for a real antivirus engine.
"""

import hashlib
import os
import database


def sha256_of_file(filepath, chunk_size=65536):
    """Return the SHA-256 hex digest of a file, or None if it can't be read."""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def scan_file(filepath):
    """
    Scan a single executable file.

    Returns a dict:
        {
            "path": str,
            "sha256": str | None,
            "malicious": bool,
            "label": str | None
        }
    """
    if not filepath or not os.path.isfile(filepath):
        return {"path": filepath, "sha256": None, "malicious": False, "label": None}

    digest = sha256_of_file(filepath)
    if digest is None:
        return {"path": filepath, "sha256": None, "malicious": False, "label": None}

    label = database.is_known_malware(digest)
    return {
        "path": filepath,
        "sha256": digest,
        "malicious": label is not None,
        "label": label,
    }


# A couple of well-known, harmless "test signature" hashes are seeded by
# default (see main.py -> seed_known_hashes) so the detector has something
# to demonstrably match against, e.g. the EICAR antivirus test file.
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = hashlib.sha256(EICAR_STRING.encode()).hexdigest()

DEFAULT_KNOWN_HASHES = {
    EICAR_SHA256: "EICAR-Test-File (safe test signature)",
}
