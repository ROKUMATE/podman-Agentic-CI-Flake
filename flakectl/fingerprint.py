"""Pillar 2 — collapse repeat sightings of one flake into one record.

``fingerprint = hash(normalised error signature + test identity)``

This is what turns model cost from O(failures) into O(distinct failure
modes). It also stabilises the output: the same flake gets the same
explanation in week three that it got in week one, because the analysis is
cached against the fingerprint rather than re-derived per sighting.

Both halves matter. The signature alone would merge "container name already
in use" across two unrelated specs; the test identity alone would split one
spec's two genuinely different failure modes into one bucket.
"""

from __future__ import annotations

import hashlib

from flakectl.models import Failure
from flakectl.normalize import error_signature

#: Length of the hex digest kept. 16 hex chars is 64 bits — ample for the
#: number of distinct failure modes a repository produces, and short enough
#: to paste into an issue title.
FINGERPRINT_LENGTH = 16


def compute_signature(failure: Failure) -> str:
    """The normalised error signature for a failure."""
    return error_signature(failure.output_block)


def compute_fingerprint(failure: Failure, signature: str | None = None) -> str:
    """Hash a failure into a stable, short fingerprint.

    Args:
        failure: The failure to fingerprint.
        signature: Precomputed signature, to avoid normalising twice.

    Returns:
        A 16-character hex fingerprint.
    """
    if signature is None:
        signature = compute_signature(failure)
    payload = f"{failure.identity}\n{signature}".encode()
    return hashlib.sha256(payload).hexdigest()[:FINGERPRINT_LENGTH]


def fingerprint_failure(failure: Failure) -> tuple[str, str]:
    """Compute both halves at once.

    Returns:
        ``(fingerprint, signature)``.
    """
    signature = compute_signature(failure)
    return compute_fingerprint(failure, signature), signature
