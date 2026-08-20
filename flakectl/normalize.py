"""Pillar 2 — strip everything non-semantic from a failure.

Two occurrences of the same flake never look byte-identical: the timestamps
differ, the container IDs differ, the temp directory differs, the port is
whatever the kernel handed out. Normalisation removes all of that. What is
left is the *shape* of the failure, which is what we hash.

Each rule is listed in :data:`NORMALIZERS` so that a maintainer debugging a
fingerprint collision can see, in order, exactly what was thrown away.
"""

from __future__ import annotations

import re

#: Ordered (pattern, replacement) pairs. Order matters: longer, more
#: specific tokens must be consumed before the general ones get to them.
NORMALIZERS: tuple[tuple[re.Pattern[str], str], ...] = (
    # UUIDs, before any hex rule can nibble at them.
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "<uuid>"),
    # Timestamps: RFC3339, Ginkgo's "@ 08/29/26 09:12:44.123", clock times.
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
     "<ts>"),
    (re.compile(r"@\s*\d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"), "@ <ts>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<ts>"),
    # IP addresses and the ephemeral ports attached to them.
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"(?<=<ip>):\d+"), ":<port>"),
    (re.compile(r"\bport\s+\d+\b", re.IGNORECASE), "port <port>"),
    # Durations. "Timed out after 3.000s" and "after 3.421s" are the same flake.
    (re.compile(r"\b\d+(?:\.\d+)?\s*(?:seconds?|secs?|minutes?|mins?|hours?)\b", re.IGNORECASE),
     "<dur>"),
    (re.compile(r"\b\d+m\d+(?:\.\d+)?s\b"), "<dur>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ns|µs|us|ms|s|h)\b"), "<dur>"),
    # Hex: memory addresses, then long IDs, then short ones. Requiring at
    # least one a-f keeps decimal values such as exit codes intact.
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<addr>"),
    (re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,64}\b"), "<id>"),
    # Process and goroutine identifiers.
    (re.compile(r"\bpid[\s=:]+\d+\b", re.IGNORECASE), "pid <pid>"),
    (re.compile(r"\bgoroutine\s+\d+\b"), "goroutine <pid>"),
    # Temporary paths: the random component makes every run look different.
    (re.compile(r"/(?:var/)?tmp/[^\s:,;'\"()\]]*"), "<tmp>"),
    (re.compile(r"\b(?:podman|buildah|ginkgo)[-_]?(?:test|e2e)?[-_]?\d{3,}\b", re.IGNORECASE),
     "<tmpname>"),
    # Ginkgo parallel node/process numbers.
    (re.compile(r"\b(?:node|proc|process)\s*#?\s*\d+\b", re.IGNORECASE), "<node>"),
    # Byte counts and line offsets that drift between runs.
    (re.compile(r"\b\d+\s*(?:bytes|KB|MB|GB|KiB|MiB|GiB)\b", re.IGNORECASE), "<size>"),
)

#: Lines that carry the actual failure, ranked by how diagnostic they are.
_ERROR_MARKERS = (
    "[failed]",
    "panic:",
    "error:",
    "expected",
    "timed out",
    "unable to",
    "cannot ",
    "failed to",
    "no such",
    "denied",
    "refused",
    "exit code",
    "exit status",
    "not found",
    "already in use",
    "already exists",
    "no space left",
    "timeout",
    "deadline exceeded",
    "connection reset",
    "no route to host",
    "too many requests",
    "rate exceeded",
    "unauthorized",
    "not supported",
    "does not support",
)

#: Lines that match a marker but carry no diagnostic content of their own —
#: the Ginkgo bullet header is the common case.
_NOISE_LINE = re.compile(r"^[•*]?\s*\[FAILED\]\s*(?:\[<dur>\])?\s*$")

#: How many diagnostic lines make up a signature.
SIGNATURE_LINES = 6


def normalize(text: str) -> str:
    """Replace every non-semantic token in ``text`` with a placeholder.

    Args:
        text: A failure's output block.

    Returns:
        The same text with timestamps, IDs, addresses, temp paths, ports,
        durations and node numbers replaced, and whitespace collapsed.
    """
    normalized = text
    for pattern, replacement in NORMALIZERS:
        normalized = pattern.sub(replacement, normalized)
    # Collapse runs of spaces/tabs but keep line structure.
    normalized = re.sub(r"[ \t]+", " ", normalized)
    return "\n".join(line.strip() for line in normalized.split("\n") if line.strip())


def error_signature(text: str, *, max_lines: int = SIGNATURE_LINES) -> str:
    """Reduce a failure block to the lines that actually describe the failure.

    Hashing the whole block would make the fingerprint sensitive to
    surrounding context; hashing one line would collide unrelated failures.
    We take the diagnostic lines, in order, deduplicated.

    Args:
        text: A failure's output block, raw or already normalised.
        max_lines: How many diagnostic lines to keep.

    Returns:
        A single-line signature, ``" | "``-separated.
    """
    normalized = normalize(text)
    lines = [line for line in normalized.split("\n") if line]
    if not lines:
        return ""

    diagnostic: list[str] = []
    seen: set[str] = set()
    for line in lines:
        lowered = line.lower()
        if _NOISE_LINE.match(line):
            continue
        if not any(marker in lowered for marker in _ERROR_MARKERS):
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        diagnostic.append(line)
        if len(diagnostic) == max_lines:
            break

    # Nothing matched a marker: fall back to the head of the block, which is
    # where Ginkgo puts the assertion.
    if not diagnostic:
        diagnostic = lines[:max_lines]

    return " | ".join(diagnostic)
