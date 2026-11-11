#!/usr/bin/env python3

"""
ruler_triage.py  v2.0.0
========================
A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers
University of Ha'il — Department of Information Security
COOP Training Project, Tahakom, 2026

Validates suspected RMM installer binaries through a six-stage evidence
pipeline, producing a calibrated confidence verdict for SOC analysts.

Pipeline
--------
1. Cryptographic hashing        (SHA-256, SHA-1, MD5)
2. Authenticode signature check  (asn1crypto + cryptography; pefile fallback)
3. VirusTotal v3 API lookup      (proactive free-tier throttle)
4. Vendor hash whitelist         (status-aware: approved / pending / blocked)
5. Confidence scoring engine     (empirically calibrated on ManageEngine case)
6. Structured report             (console + JSON; case-validation annex)

Usage
-----
  python ruler_triage.py <FILE> [options]

  --vt-key  <KEY>          VirusTotal v3 API key (or set VT_API_KEY env var)
  --db      <PATH>         Vendor hash JSON database  [default: vendor_hashes.json]
  --out     <PATH>         Write JSON report to this file
  --vt-delay <SECONDS>     Proactive throttle between VT requests  [default: 15]
  --add-to-db <sha256:vendor:product>  Append a new hash entry to the DB
  --validate-case          Run self-validation against the ManageEngine ground-truth

Dependencies
------------
  pip install requests pefile colorama asn1crypto cryptography

  pefile, asn1crypto, cryptography, colorama are optional — the tool degrades
  gracefully when they are absent.
"""

# ════════════════════════════════════════════════════════════════════════════
# Standard library imports
# ════════════════════════════════════════════════════════════════════════════
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ════════════════════════════════════════════════════════════════════════════
# Third-party imports — each with graceful degradation
# ════════════════════════════════════════════════════════════════════════════
import requests

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False

# Authenticode / ASN.1 stack — used for real cryptographic verification
# Library choice rationale:
#   asn1crypto  — pure-Python, no OpenSSL dependency, reliable PKCS#7/CMS parsing
#   cryptography — Rust-backed, provides hashing primitives matching PE digest
#   Together they let us verify the SignedData messageDigest against the PE
#   Authenticode hash without shelling out to signtool or openssl.
try:
    from asn1crypto import cms, pem, core
    _ASN1_AVAILABLE = True
except ImportError:
    _ASN1_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes as _cry_hashes
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.x509.oid import NameOID
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ════════════════════════════════════════════════════════════════════════════
# Ground-truth case reference (Tahakom COOP investigation, 2026-07-19)
# ════════════════════════════════════════════════════════════════════════════
GROUND_TRUTH_CASE = {
    "name":            "ManageEngine UEMS Agent — Tahakom COOP Investigation",
    "sha256":          "eddb6acad4b6078e7a691d4fb8c452916efd288f27eb99a8426a2b81dfa5539c",
    "date":            "2026-07-19",
    "artifact":        "Suspicious File.zip (password: virus, recovered via zip2john + john)",
    "network":         "SMB2 / port 445 / internal-to-internal (10.x.x.20 → 10.x.x.128)",
    "binary_name":     "InstallShield Setup.exe",
    "vt_ratio":        "1/69 (ESET: RemoteAdmin)",
    "signed":          False,
    "sandbox_result":  "Clean — standard InstallShield unpacking, no malicious indicators",
    "final_verdict":   "Low Confidence (Suspicious / Pending Verification)",
    "expected_score":  20,
    "recommendation":  (
        "Confirm with IT Operations whether the ManageEngine UEMS deployment "
        "was authorised before closing the alert."
    ),
}

# ════════════════════════════════════════════════════════════════════════════
# Scoring rationale — empirically calibrated against the ManageEngine case
# ════════════════════════════════════════════════════════════════════════════
SCORING_RATIONALE = {
    "unsigned": (
        "In the ManageEngine UEMS case (Tahakom COOP), the unsigned binary was the "
        "primary IDS trigger and the main reason the analyst retained a Low-Confidence "
        "verdict rather than closing as False Positive. Unsigned RMM installers are "
        "atypical for enterprise-grade software and warrant scrutiny. Weight: +30."
    ),
    "signed_invalid": (
        "A structurally present but cryptographically invalid signature is more "
        "suspicious than simply unsigned — it may indicate tampering or certificate "
        "stripping. Treated identically to Unsigned. Weight: +30."
    ),
    "vt_any_detection": (
        "Any VT detection (even 1/69) is significant for RMM installers because "
        "legitimate enterprise RMM binaries are typically not flagged. In the UEMS "
        "case, ESET flagged it as 'RemoteAdmin' — a dual-use classification that "
        "elevates rather than eliminates suspicion. Weight: +20."
    ),
    "vt_high_detection": (
        "A detection rate above 5 % of scanning engines is a strong malice indicator "
        "even for dual-use tools. Applied as an additional bonus on top of the base "
        "detection score. Weight: +20 (additive)."
    ),
    "whitelist_approved": (
        "A match against a corporately-approved hash is the strongest known-good signal "
        "available without endpoint telemetry. It should override most other indicators "
        "to prevent false positives on authorised RMM deployments. Weight: −80."
    ),
    "whitelist_pending": (
        "A 'pending_verification' entry means the hash is known but the deployment has "
        "not yet been confirmed by IT Operations — the exact situation in the Tahakom "
        "COOP case. Weight −30 was calibrated so that the full ManageEngine UEMS score "
        "(Unsigned +30, VT 1/69 +20, pending −30) equals +20, which falls below the "
        "Low-Confidence threshold of 30, exactly matching the manual analyst verdict. "
        "A warning is always appended to the report prompting IT Ops confirmation."
    ),
    "whitelist_blocked": (
        "A 'blocked' entry is an explicit deny-list hit. Treated as strong malice "
        "evidence. Weight: +40."
    ),
    "whitelist_miss": (
        "A hash absent from the vendor database is mildly suspicious for the RMM "
        "installer category, where enterprise tools are typically centrally managed "
        "and should appear in corporate asset inventories. Weight: +10."
    ),
}

# ════════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════════
_TOOL_VERSION   = "2.0.0"
_TOOL_NAME      = "ruler_triage.py"
_PROJECT_TITLE  = (
    "A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers"
)
_INSTITUTION    = "University of Ha'il — Department of Information Security"

VT_API_BASE          = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_PAUSE  = 60   # seconds to wait after HTTP 429  (free tier: 4 req/min)
VT_PROACTIVE_DELAY   = 15   # seconds between proactive requests (free-tier safe)
VT_REQUEST_TIMEOUT   = 30   # seconds per HTTP call

DEFAULT_DB_PATH = Path(__file__).parent / "vendor_hashes.json"

# Scoring weights
SCORE_UNSIGNED            = 30
SCORE_VT_ANY_DETECTION    = 20
SCORE_VT_HIGH_DETECTION   = 20   # additive bonus
SCORE_WHITELIST_APPROVED  = -80  # known-good override
SCORE_WHITELIST_PENDING   = -30  # known-but-unverified
                                  # Calibrated so that the ManageEngine UEMS case
                                  # (Unsigned +30, VT 1/69 +20, pending -30) = 20
                                  # → Low Confidence, matching the Tahakom manual verdict.
SCORE_WHITELIST_BLOCKED   = +40  # explicit deny-list
SCORE_WHITELIST_MISS      = +10  # not recognised

VERDICT_THRESHOLDS = {
    "high":   60,   # ≥ 60  → High Confidence (Malicious)
    "medium": 30,   # 30–59 → Medium Confidence (Likely Malicious)
    #  < 30          → Low Confidence (Suspicious / Pending Verification)
}

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Module-level timestamp of the last VT request (for proactive throttle)
_vt_last_request_ts: float = 0.0
_QUIET: bool = False


# ════════════════════════════════════════════════════════════════════════════
# Helper utilities
# ════════════════════════════════════════════════════════════════════════════

def _c(color_code: str, text: str) -> str:
    """Wrap text in a colorama colour code if colour is available."""
    if not _COLOR:
        return text
    reset = Style.RESET_ALL
    return f"{color_code}{text}{reset}"


def _info(msg: str) -> None:
    if not _QUIET:
        print(_c(Fore.GREEN if _COLOR else "", "[INFO] ") + msg)


def _warn(msg: str) -> None:
    print(_c(Fore.YELLOW if _COLOR else "", "[WARN] ") + msg, file=sys.stderr)


def _err(msg: str) -> None:
    print(_c(Fore.RED if _COLOR else "", "[ERR ] ") + msg, file=sys.stderr)


def _bold(text: str) -> str:
    if not _COLOR:
        return text
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


def _short(value: str, n: int = 26) -> str:
    """Truncate a table cell to a fixed display width, adding an ellipsis."""
    value = str(value)
    if len(value) <= n:
        return value
    return value[: max(0, n - 1)] + "…"


# ════════════════════════════════════════════════════════════════════════════
# MODULE 1 — Cryptographic Hashing
# ════════════════════════════════════════════════════════════════════════════

def compute_hashes(file_path: Path) -> dict:
    """
    Stream the file in 1-MiB chunks and compute SHA-256, SHA-1, and MD5
    in a single pass.

    Args:
        file_path: Resolved path to the binary.

    Returns:
        {'sha256': str, 'sha1': str, 'md5': str}

    Raises:
        FileNotFoundError, PermissionError, OSError
    """
    h256 = hashlib.sha256()
    h1   = hashlib.sha1()
    hmd5 = hashlib.md5()

    with open(file_path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h256.update(chunk)
            h1.update(chunk)
            hmd5.update(chunk)

    return {
        "sha256": h256.hexdigest(),
        "sha1":   h1.hexdigest(),
        "md5":    hmd5.hexdigest(),
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE 2 — Digital Signature Verification
# ════════════════════════════════════════════════════════════════════════════
#
# Verification strategy (in order of capability):
#
#  Tier 1 — Full cryptographic verification (asn1crypto + cryptography)
#    Parse the WIN_CERTIFICATE PKCS#7 / CMS SignedData blob, extract the
#    SignerInfo messageDigest, recompute the Authenticode hash of the PE
#    (HashAlgorithm from the SignerInfo), and compare. Also extract the
#    leaf certificate's CN and expiry.  Does NOT verify the chain to a
#    trusted root (that requires Windows CryptoAPI or a root store).
#
#  Tier 2 — Structural verification (pefile only)
#    Confirms the WIN_CERTIFICATE header is well-formed (correct type byte
#    0x0002 and non-trivial length). Cannot detect a valid-looking but
#    tampered digest. Returns "Signed-Structural" to signal lower confidence.
#
#  Tier 3 — No PE library available
#    Returns "Unknown" with a clear degradation warning.

def _authenticode_hash(file_path: Path, alg_name: str) -> bytes:
    """
    Compute the Authenticode hash of a PE file.

    Authenticode hashing excludes:
      - The 4-byte CheckSum field in the Optional Header
      - The 8-byte Security Directory entry (VirtualAddress + Size)
      - The PKCS#7 blob itself (the Security Directory data)

    Reference: Microsoft PE/COFF Specification §8 — Authenticode Signing.

    Args:
        file_path: Path to PE binary.
        alg_name:  Hash algorithm name as recognised by hashlib ('sha1', 'sha256').

    Returns:
        Raw hash digest bytes.
    """
    data = file_path.read_bytes()

    # ── Parse the PE header to locate exclusion ranges ──────────────────────
    # DOS header → e_lfanew at offset 0x3C (4 bytes LE)
    if len(data) < 0x40:
        raise ValueError("File too small to be a valid PE.")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    pe_sig_off = e_lfanew          # 'PE\0\0'
    coff_off   = pe_sig_off + 4    # COFF file header starts here
    opt_off    = coff_off + 20     # Optional header starts here

    # Determine PE32 vs PE32+
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x10B:
        checksum_off = opt_off + 64        # CheckSum is at opt+64 in PE32
        dd_off       = opt_off + 96        # Data directories start at opt+96
    elif magic == 0x20B:
        checksum_off = opt_off + 64        # same offset in PE32+
        dd_off       = opt_off + 112       # Data directories start at opt+112
    else:
        raise ValueError(f"Unknown PE Optional Header magic: 0x{magic:04X}")

    # Security Directory is DataDirectory[4] — each entry is 8 bytes (VA+Size)
    sec_dir_off  = dd_off + 4 * 8          # entry 4 * 8 bytes each
    sec_dir_va   = struct.unpack_from("<I", data, sec_dir_off)[0]
    sec_dir_size = struct.unpack_from("<I", data, sec_dir_off + 4)[0]

    # Build list of byte ranges to hash (everything except the exclusions)
    h = hashlib.new(alg_name)

    def _hash_range(start: int, end: int) -> None:
        h.update(data[start:end])

    # Region 1: start → checksum
    _hash_range(0, checksum_off)
    # Region 2: checksum+4 → security directory entry
    _hash_range(checksum_off + 4, sec_dir_off)
    # Region 3: security directory entry+8 → start of certificate table
    _hash_range(sec_dir_off + 8, sec_dir_va if sec_dir_va else len(data))
    # Region 4: everything after the certificate table (if any trailing data)
    if sec_dir_va and sec_dir_size:
        cert_end = sec_dir_va + sec_dir_size
        if cert_end < len(data):
            _hash_range(cert_end, len(data))

    return h.digest()


def _verify_authenticode_full(file_path: Path, cert_data: bytes) -> tuple[str, str, str]:
    """
    Tier-1 verification using asn1crypto + cryptography.

    Parses the PKCS#7/CMS SignedData blob, extracts the messageDigest
    attribute from SignerInfo, recomputes the Authenticode hash using the
    algorithm declared in the SignerInfo, and compares them.

    Args:
        file_path:  Path to the PE binary.
        cert_data:  Raw WIN_CERTIFICATE payload (after the 8-byte header).

    Returns:
        (status, signer_cn, expiry_iso)
        status: "Signed-Valid" | "Signed-Invalid"
    """
    try:
        content_info = cms.ContentInfo.load(cert_data)
        signed_data  = content_info["content"].parsed

        # Extract the first SignerInfo
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) == 0:
            return "Signed-Invalid", "(no signer info)", ""

        si = signer_infos[0]

        # Determine the digest algorithm
        digest_alg_oid = si["digest_algorithm"]["algorithm"].dotted
        alg_map = {
            "1.3.14.3.2.26":        "sha1",
            "2.16.840.1.101.3.4.2.1": "sha256",
            "2.16.840.1.101.3.4.2.2": "sha384",
            "2.16.840.1.101.3.4.2.3": "sha512",
        }
        alg_name = alg_map.get(digest_alg_oid)
        if alg_name is None:
            return "Signed-Invalid", f"(unsupported digest alg: {digest_alg_oid})", ""

        # Extract the claimed messageDigest from SignerInfo attributes
        claimed_digest: Optional[bytes] = None
        signed_attrs = si["signed_attrs"]
        for attr in signed_attrs:
            if attr["type"].dotted == "1.2.840.113549.1.9.4":   # messageDigest OID
                claimed_digest = attr["values"][0].parsed.native
                break

        if claimed_digest is None:
            return "Signed-Invalid", "(messageDigest attribute missing)", ""

        # Recompute the Authenticode hash
        actual_digest = _authenticode_hash(file_path, alg_name)

        # Compare
        if actual_digest != claimed_digest:
            return "Signed-Invalid", "(digest mismatch — possible tampering)", ""

        # Extract signer CN and expiry from the leaf certificate
        signer_cn  = "(unknown CN)"
        expiry_iso = ""
        certs = signed_data["certificates"]
        if certs is not None and len(certs) > 0:
            try:
                cert_choice = certs[0]
                der_bytes   = cert_choice.chosen.dump()
                x509 = load_der_x509_certificate(der_bytes)
                try:
                    signer_cn = x509.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except (IndexError, Exception):
                    signer_cn = "(CN not found)"
                expiry_iso = x509.not_valid_after_utc.isoformat()
            except Exception:
                signer_cn = "(cert parse error)"

        return "Signed-Valid", signer_cn, expiry_iso

    except Exception as exc:
        return "Signed-Invalid", f"(ASN.1 parse error: {exc})", ""


def _verify_authenticode_structural(cert_data: bytes) -> tuple[str, str]:
    """
    Tier-2 verification using pefile only.

    Validates the WIN_CERTIFICATE header structure (type == 0x0002,
    non-trivial length) without recomputing the digest.  Cannot detect
    valid-looking tampered certificates — returns "Signed-Structural"
    to signal this limitation.

    Args:
        cert_data: Raw bytes starting at the WIN_CERTIFICATE dwLength field.

    Returns:
        (status, detail)
    """
    if len(cert_data) < 8:
        return "Signed-Invalid", "WIN_CERTIFICATE data too short (< 8 bytes)."

    dw_length, w_revision, w_cert_type = struct.unpack_from("<IHH", cert_data, 0)
    WIN_CERT_TYPE_PKCS7 = 0x0002

    if w_cert_type != WIN_CERT_TYPE_PKCS7:
        return (
            "Signed-Invalid",
            f"Unexpected certificate type 0x{w_cert_type:04X} (expected 0x0002 PKCS#7).",
        )

    if dw_length < 16:
        return "Signed-Invalid", f"WIN_CERTIFICATE dwLength ({dw_length}) implausibly small."

    hint = _extract_signer_hint(cert_data[8:])
    return (
        "Signed-Structural",
        f"PKCS#7 header valid (digest not verified). Signer hint: {hint}",
    )


def _extract_signer_hint(der_bytes: bytes) -> str:
    """Scan raw DER for printable ASCII runs that resemble a CN/org field."""
    buf: list[str] = []
    runs: list[str] = []
    for byte in der_bytes:
        if 0x20 <= byte <= 0x7E:
            buf.append(chr(byte))
        else:
            if len(buf) >= 6:
                runs.append("".join(buf))
            buf = []
    if len(buf) >= 6:
        runs.append("".join(buf))
    return max(runs, key=len)[:120] if runs else "(could not extract)"


def check_signature(file_path: Path) -> dict:
    """
    Public entry point for signature verification.

    Attempts Tier-1 (full cryptographic) → Tier-2 (structural) → Tier-3 (none).

    Returns:
        {
          'status':     str,   # Signed-Valid | Signed-Structural | Signed-Invalid
                               #   | Unsigned | Not a PE | Unknown
          'signer_cn':  str,
          'expiry':     str,   # ISO-8601 or ''
          'detail':     str,
          'tier':       int,   # 1 | 2 | 3
        }
    """
    if not _PEFILE_AVAILABLE:
        return {
            "status":    "Unknown",
            "signer_cn": "",
            "expiry":    "",
            "detail":    (
                "pefile is not installed — signature inspection unavailable. "
                "Install with: pip install pefile"
            ),
            "tier": 3,
        }

    # Parse the PE and locate the Security Directory
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
    except pefile.PEFormatError as exc:
        return {
            "status":    "Not a PE",
            "signer_cn": "",
            "expiry":    "",
            "detail":    f"pefile parse error: {exc}",
            "tier": 2,
        }
    except Exception as exc:
        return {
            "status":    "Unknown",
            "signer_cn": "",
            "expiry":    "",
            "detail":    f"Unexpected PE load error: {exc}",
            "tier": 2,
        }

    if not hasattr(pe, "DIRECTORY_ENTRY_SECURITY") or not pe.DIRECTORY_ENTRY_SECURITY:
        return {
            "status":    "Unsigned",
            "signer_cn": "",
            "expiry":    "",
            "detail":    "No Security Directory found in PE headers.",
            "tier": 2,
        }

    raw_cert = pe.DIRECTORY_ENTRY_SECURITY[0].get_data()

    # Tier 1 — full verification
    if _ASN1_AVAILABLE and _CRYPTO_AVAILABLE:
        payload = raw_cert[8:]  # skip the 8-byte WIN_CERTIFICATE header
        status, signer_cn, expiry = _verify_authenticode_full(file_path, payload)
        return {
            "status":    status,
            "signer_cn": signer_cn,
            "expiry":    expiry,
            "detail":    (
                f"Authenticode digest {'verified' if status == 'Signed-Valid' else 'FAILED'} "
                f"(Tier-1 / asn1crypto + cryptography). "
                f"CN: {signer_cn}. Expiry: {expiry or 'N/A'}."
            ),
            "tier": 1,
        }

    # Tier 2 — structural only
    status, detail = _verify_authenticode_structural(raw_cert)
    if not _ASN1_AVAILABLE or not _CRYPTO_AVAILABLE:
        detail += (
            "  [Tier-2 — asn1crypto/cryptography not installed; "
            "digest not verified. pip install asn1crypto cryptography]"
        )
    return {
        "status":    status,
        "signer_cn": "",
        "expiry":    "",
        "detail":    detail,
        "tier": 2,
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE 3 — VirusTotal API Integration
# ════════════════════════════════════════════════════════════════════════════

def query_virustotal(sha256: str, api_key: str, proactive_delay: int = VT_PROACTIVE_DELAY) -> dict:
    """
    Query the VirusTotal v3 /files/{hash} endpoint.

    Rate-limit handling:
      - Proactive throttle: if < proactive_delay seconds have elapsed since
        the last successful request, sleep the remainder before issuing the
        next one.  Safe default for the free tier (4 requests/minute).
      - Reactive back-off: HTTP 429 triggers a VT_RATE_LIMIT_PAUSE=60s sleep
        and a retry (up to 3 attempts).

    Free-tier note:  Public API key = 4 requests/minute, 500/day.
    The file is NEVER uploaded — only the hash is sent.

    Returns:
        {
          'found':           bool,
          'detection_ratio': str,      # e.g. "1/69"
          'malicious':       int,
          'suspicious':      int,
          'total_engines':   int,
          'community_score': int,
          'permalink':       str,
          'error':           str | None,
        }
    """
    global _vt_last_request_ts

    if not api_key:
        return _vt_error(
            "No VirusTotal API key provided. Running in offline mode — "
            "VT intelligence is unavailable. Accuracy is reduced. "
            "Provide a key with --vt-key or the VT_API_KEY environment variable."
        )

    # Proactive throttle
    elapsed = time.monotonic() - _vt_last_request_ts
    if elapsed < proactive_delay:
        sleep_for = proactive_delay - elapsed
        _info(
            f"VT proactive throttle: waiting {sleep_for:.1f}s "
            f"(free tier = 4 req/min; use --vt-delay to adjust)…"
        )
        time.sleep(sleep_for)

    url     = f"{VT_API_BASE}/files/{sha256}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    for attempt in range(1, 4):
        try:
            resp = requests.get(url, headers=headers, timeout=VT_REQUEST_TIMEOUT)
            _vt_last_request_ts = time.monotonic()
        except requests.exceptions.Timeout:
            return _vt_error(
                f"Request timed out after {VT_REQUEST_TIMEOUT}s (attempt {attempt}/3)."
            )
        except requests.exceptions.ConnectionError as exc:
            return _vt_error(f"Network error: {exc}")

        if resp.status_code == 429:
            _warn(
                f"VT rate limit hit (HTTP 429) — free tier allows 4 req/min. "
                f"Waiting {VT_RATE_LIMIT_PAUSE}s (attempt {attempt}/3)…"
            )
            time.sleep(VT_RATE_LIMIT_PAUSE)
            continue

        if resp.status_code == 404:
            return {
                "found":           False,
                "detection_ratio": "0/0",
                "malicious":       0,
                "suspicious":      0,
                "total_engines":   0,
                "community_score": 0,
                "permalink":       f"https://www.virustotal.com/gui/file/{sha256}",
                "error":           None,
            }

        if resp.status_code == 401:
            return _vt_error("Invalid or unauthorised API key (HTTP 401).")

        if not resp.ok:
            return _vt_error(f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}")

        attrs   = resp.json().get("data", {}).get("attributes", {})
        stats   = attrs.get("last_analysis_stats", {})
        mal     = stats.get("malicious", 0)
        sus     = stats.get("suspicious", 0)
        total   = sum(stats.values()) if stats else 0
        flagged = mal + sus

        return {
            "found":           True,
            "detection_ratio": f"{flagged}/{total}",
            "malicious":       mal,
            "suspicious":      sus,
            "total_engines":   total,
            "community_score": attrs.get("reputation", 0),
            "permalink":       f"https://www.virustotal.com/gui/file/{sha256}",
            "error":           None,
        }

    return _vt_error(
        "Exceeded retry limit (3 attempts) due to VT rate limiting. "
        "Free tier: 4 requests/minute."
    )


def _vt_error(msg: str) -> dict:
    return {
        "found":           False,
        "detection_ratio": "N/A",
        "malicious":       0,
        "suspicious":      0,
        "total_engines":   0,
        "community_score": 0,
        "permalink":       "",
        "error":           msg,
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Vendor Hash Database
# ════════════════════════════════════════════════════════════════════════════

def load_vendor_db(db_path: Path) -> dict:
    """
    Load the vendor whitelist/blocklist from a JSON file.

    Schema per entry:
        {
          "vendor":   str,
          "product":  str,
          "version":  str,
          "status":   "approved" | "pending_verification" | "blocked",
          "notes":    str   (optional)
        }

    Legacy entries that use 'approved': true/false are silently migrated
    to the status field ('approved' / 'pending_verification').

    Keys starting with '_' are treated as metadata/comments and ignored.

    Returns an empty dict (non-fatal) if the file is missing or malformed.
    """
    if not db_path.exists():
        _warn(f"Vendor DB not found at '{db_path}' — whitelist check skipped.")
        return {}
    try:
        with open(db_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("Root element must be a JSON object.")

        db: dict = {}
        for key, val in raw.items():
            if key.startswith("_"):   # skip metadata keys
                continue
            if not isinstance(val, dict):
                continue
            # Migrate legacy 'approved' bool to status string
            if "status" not in val:
                if val.get("approved") is True:
                    val["status"] = "approved"
                elif val.get("pending_verification") is True:
                    val["status"] = "pending_verification"
                else:
                    val["status"] = "approved"   # safe default for old entries
            db[key.lower()] = val
        return db

    except (json.JSONDecodeError, ValueError) as exc:
        _warn(f"Vendor DB parse error: {exc} — whitelist check skipped.")
        return {}


def check_whitelist(sha256: str, vendor_db: dict) -> dict:
    """
    Look up a SHA-256 hash in the vendor database.

    Returns:
        {
          'match':   bool,
          'status':  str,   # 'approved' | 'pending_verification' | 'blocked' | None
          'vendor':  str | None,
          'product': str | None,
          'version': str | None,
          'notes':   str | None,
        }
    """
    entry = vendor_db.get(sha256.lower())
    if entry:
        return {
            "match":   True,
            "status":  entry.get("status", "approved"),
            "vendor":  entry.get("vendor"),
            "product": entry.get("product"),
            "version": entry.get("version"),
            "notes":   entry.get("notes", ""),
        }
    return {
        "match":   False,
        "status":  None,
        "vendor":  None,
        "product": None,
        "version": None,
        "notes":   None,
    }


def add_hash_to_db(db_path: Path, sha256: str, vendor: str, product: str,
                   status: str = "pending_verification") -> None:
    """
    Append a new hash entry to the vendor database JSON file.

    Args:
        db_path:  Path to vendor_hashes.json.
        sha256:   64-character hex SHA-256 digest.
        vendor:   Vendor name string.
        product:  Product/binary name.
        status:   'approved' | 'pending_verification' | 'blocked'

    Raises:
        ValueError: If sha256 format is invalid.
        OSError:    If the file cannot be read or written.
    """
    if not SHA256_RE.match(sha256):
        raise ValueError(
            f"Invalid SHA-256 format: '{sha256}'. Must be 64 hexadecimal characters."
        )

    if db_path.exists():
        with open(db_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = {
            "_comment":      "Ruler Triage Framework — Vendor Hash Database",
            "_last_updated": datetime.now(timezone.utc).date().isoformat(),
        }

    key = sha256.lower()
    data[key] = {
        "vendor":       vendor,
        "product":      product,
        "version":      "user-added",
        "status":       status,
        "added_by":     "ruler_triage --add-to-db",
        "added_date":   datetime.now(timezone.utc).date().isoformat(),
        "notes":        "",
    }
    with open(db_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    _info(f"Added {sha256[:16]}… to {db_path} (status: {status}).")


# ════════════════════════════════════════════════════════════════════════════
# MODULE 5 — Confidence Scoring Engine
# ════════════════════════════════════════════════════════════════════════════

def compute_verdict(sig: dict, vt: dict, whitelist: dict) -> dict:
    """
    Heuristic confidence scoring engine.

    Weights are empirically calibrated against the ManageEngine UEMS
    ground-truth case (Tahakom COOP, 2026-07-19).  See SCORING_RATIONALE
    for the academic justification of each weight.

    Scoring table
    ─────────────────────────────────────────────────────────────────────────
    Indicator                                 Points   Rationale key
    ─────────────────────────────────────────────────────────────────────────
    Unsigned or Invalid Signature             +30      unsigned / signed_invalid
    Any VT detections (malicious+susp > 0)    +20      vt_any_detection
    High VT rate  (> 5 % of engines)          +20      vt_high_detection
    DB: entry not found                       +10      whitelist_miss
    DB: pending_verification match            −30      whitelist_pending
    DB: approved match                        −80      whitelist_approved
    DB: blocked match                         +40      whitelist_blocked
    ─────────────────────────────────────────────────────────────────────────

    Verdict thresholds
    ─────────────────────────────────────────────────────────────────────────
    ≥ 60  → High Confidence (Malicious)
    30–59 → Medium Confidence (Likely Malicious)
    < 30  → Low Confidence (Suspicious / Pending Verification)
    ─────────────────────────────────────────────────────────────────────────
    """
    score   = 0
    reasons = []
    warnings: list[str] = []

    # ── Signature ────────────────────────────────────────────────────────────
    sig_status = sig.get("status", "Unknown")
    if sig_status in ("Unsigned",):
        score += SCORE_UNSIGNED
        reasons.append(
            f"+{SCORE_UNSIGNED}  Unsigned binary — no Authenticode signature detected."
        )
    elif sig_status in ("Signed-Invalid", "Invalid Signature"):
        score += SCORE_UNSIGNED
        reasons.append(
            f"+{SCORE_UNSIGNED}  Invalid/tampered Authenticode signature."
        )
    elif sig_status == "Signed-Valid":
        cn     = sig.get("signer_cn", "")
        expiry = sig.get("expiry", "")
        reasons.append(
            f" ±0  Signed-Valid: CN={cn or 'N/A'}, Expiry={expiry or 'N/A'}."
        )
    elif sig_status == "Signed-Structural":
        # Presence confirmed but digest not verified — moderate concern
        score += 10
        reasons.append(
            f"+10  Signed (structural check only — digest not verified). "
            f"Consider installing asn1crypto+cryptography for full verification."
        )
        warnings.append(
            "Signature presence confirmed but digest not cryptographically verified. "
            "Install asn1crypto and cryptography for Tier-1 verification."
        )
    else:
        reasons.append(f" ±0  Signature status unknown ({sig_status}) — skipped.")

    # ── VirusTotal ───────────────────────────────────────────────────────────
    malicious = vt.get("malicious", 0)
    total     = vt.get("total_engines", 0)

    if vt.get("error") and not vt.get("found"):
        reasons.append(f" ±0  VT unavailable: {vt['error']}")
        warnings.append("VT intelligence absent — verdict accuracy is reduced.")
    elif not vt.get("found"):
        reasons.append(" ±0  Hash not yet indexed by VirusTotal.")
    else:
        flagged = malicious + vt.get("suspicious", 0)
        if flagged > 0:
            score += SCORE_VT_ANY_DETECTION
            reasons.append(
                f"+{SCORE_VT_ANY_DETECTION}  VT detection ratio: "
                f"{vt['detection_ratio']} engines flagged."
            )
            if total > 0 and (malicious / total) > 0.05:
                score += SCORE_VT_HIGH_DETECTION
                reasons.append(
                    f"+{SCORE_VT_HIGH_DETECTION}  High detection rate "
                    f"({malicious}/{total} > 5 % threshold)."
                )
        else:
            reasons.append(
                f" ±0  VT: {vt['detection_ratio']} — no engines flagged."
            )

    # ── Vendor Whitelist ─────────────────────────────────────────────────────
    wl_status = whitelist.get("status")
    if not whitelist.get("match"):
        score += SCORE_WHITELIST_MISS
        reasons.append(
            f"+{SCORE_WHITELIST_MISS}  Hash not found in vendor database."
        )
    elif wl_status == "approved":
        score += SCORE_WHITELIST_APPROVED
        reasons.append(
            f"{SCORE_WHITELIST_APPROVED}  DB match (APPROVED): "
            f"{whitelist.get('vendor')} — {whitelist.get('product')} "
            f"v{whitelist.get('version')}."
        )
    elif wl_status == "pending_verification":
        score += SCORE_WHITELIST_PENDING
        reasons.append(
            f"{SCORE_WHITELIST_PENDING}  DB match (PENDING VERIFICATION): "
            f"{whitelist.get('vendor')} — {whitelist.get('product')}. "
            f"Hash is known but deployment NOT yet confirmed by IT Operations."
        )
        warnings.append(
            "This hash is in the vendor database as PENDING VERIFICATION. "
            "Confirm with IT Operations before closing the alert. "
            f"Notes: {whitelist.get('notes', 'N/A')}"
        )
    elif wl_status == "blocked":
        score += SCORE_WHITELIST_BLOCKED
        reasons.append(
            f"+{SCORE_WHITELIST_BLOCKED}  DB match (BLOCKED / DENY-LIST): "
            f"{whitelist.get('vendor')} — {whitelist.get('product')}."
        )
        warnings.append(
            "This hash is on the explicit block-list. Treat as confirmed malicious "
            "regardless of other indicators."
        )

    # ── Final verdict ────────────────────────────────────────────────────────
    if score >= VERDICT_THRESHOLDS["high"]:
        verdict = "High Confidence (Malicious)"
        color   = Fore.RED if _COLOR else ""
    elif score >= VERDICT_THRESHOLDS["medium"]:
        verdict = "Medium Confidence (Likely Malicious)"
        color   = Fore.YELLOW if _COLOR else ""
    else:
        verdict = "Low Confidence (Suspicious / Pending Verification)"
        color   = Fore.CYAN if _COLOR else ""

    return {
        "score":    score,
        "verdict":  verdict,
        "color":    color,
        "reasons":  reasons,
        "warnings": warnings,
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE 6 — Case Validation Reference
# ════════════════════════════════════════════════════════════════════════════

def build_case_validation(sha256: str, verdict: dict) -> dict:
    """
    Compare the current analysis result against the ManageEngine ground-truth.

    Returns a dict that is included in both the console output and JSON report.
    """
    gt = GROUND_TRUTH_CASE
    is_ground_truth_hash = sha256.lower() == gt["sha256"].lower()

    # Determine whether the verdict category matches
    def _category(v: str) -> str:
        if "High" in v:   return "high"
        if "Medium" in v: return "medium"
        return "low"

    current_cat  = _category(verdict["verdict"])
    expected_cat = _category(gt["final_verdict"])
    categories_match = current_cat == expected_cat

    framework_confidence: str
    if is_ground_truth_hash:
        if categories_match:
            framework_confidence = (
                "VALIDATED — Tool verdict matches ground-truth investigation "
                "for the ManageEngine UEMS Tahakom case."
            )
        else:
            framework_confidence = (
                "CALIBRATION MISMATCH — Tool verdict differs from the "
                "expected ground-truth verdict. Review scoring weights."
            )
    else:
        framework_confidence = (
            "Not the ground-truth hash — comparison is informational only."
        )

    return {
        "ground_truth_name":      gt["name"],
        "ground_truth_sha256":    gt["sha256"],
        "ground_truth_verdict":   gt["final_verdict"],
        "ground_truth_score":     gt["expected_score"],
        "current_sha256":         sha256,
        "current_verdict":        verdict["verdict"],
        "current_score":          verdict["score"],
        "is_ground_truth_hash":   is_ground_truth_hash,
        "verdict_category_match": categories_match,
        "framework_confidence":   framework_confidence,
        "ground_truth_reference": {
            "date":     gt["date"],
            "network":  gt["network"],
            "vt_ratio": gt["vt_ratio"],
            "sandbox":  gt["sandbox_result"],
        },
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE 7 — Report Builder
# ════════════════════════════════════════════════════════════════════════════

def build_report(
    file_path: Path,
    hashes: dict,
    sig: dict,
    vt: dict,
    whitelist: dict,
    verdict: dict,
    case_validation: dict,
) -> dict:
    """Assemble all findings into a structured report dict."""
    return {
        "report_meta": {
            "tool":        _TOOL_NAME,
            "version":     _TOOL_VERSION,
            "project":     _PROJECT_TITLE,
            "institution": _INSTITUTION,
            "generated":   datetime.now(timezone.utc).isoformat(),
        },
        "target_file": {
            "path":       str(file_path.resolve()),
            "filename":   file_path.name,
            "size_bytes": file_path.stat().st_size,
        },
        "hashes":    hashes,
        "signature": {k: v for k, v in sig.items() if k != "color"},
        "virustotal": {k: v for k, v in vt.items() if k != "color"},
        "whitelist_check": whitelist,
        "verdict": {
            "score":    verdict["score"],
            "verdict":  verdict["verdict"],
            "reasons":  verdict["reasons"],
            "warnings": verdict["warnings"],
        },
        "case_validation": case_validation,
        "scoring_rationale_ref": "See SCORING_RATIONALE constant in ruler_triage.py",
    }


def print_report(report: dict, verdict_color: str) -> None:
    """Pretty-print the full report to stdout."""
    SEP  = "═" * 72
    SEP2 = "─" * 72

    print(f"\n{_bold(SEP)}")
    print(_bold(f"  {_TOOL_NAME} v{_TOOL_VERSION}  —  TRIAGE ANALYSIS REPORT"))
    print(_bold(f"  {_PROJECT_TITLE}"))
    print(_bold(f"  {_INSTITUTION}"))
    print(_bold(SEP))

    meta = report["report_meta"]
    tgt  = report["target_file"]
    print(f"\n{_c(Fore.CYAN if _COLOR else '', 'Generated')}: {meta['generated']}")
    print(f"{_c(Fore.CYAN if _COLOR else '', 'File     ')}: {tgt['filename']}")
    print(f"{_c(Fore.CYAN if _COLOR else '', 'Path     ')}: {tgt['path']}")
    print(f"{_c(Fore.CYAN if _COLOR else '', 'Size     ')}: {tgt['size_bytes']:,} bytes")

    # Hashes
    print(f"\n{_bold('── 1. Cryptographic Hashes ' + SEP2[26:])}")
    h = report["hashes"]
    print(f"  SHA-256 : {h['sha256']}")
    print(f"  SHA-1   : {h['sha1']}")
    print(f"  MD5     : {h['md5']}")

    # Signature
    print(f"\n{_bold('── 2. Digital Signature ' + SEP2[22:])}")
    s = report["signature"]
    tier_label = {1: "Tier-1 (full crypto)", 2: "Tier-2 (structural)", 3: "Tier-3 (none)"}.get(
        s.get("tier", 3), ""
    )
    status_color = (
        (Fore.GREEN  if _COLOR else "") if s["status"] == "Signed-Valid"
        else (Fore.RED if _COLOR else "") if s["status"] in ("Unsigned", "Signed-Invalid", "Invalid Signature")
        else (Fore.YELLOW if _COLOR else "")
    )
    print(f"  Status  : {_c(status_color, s['status'])}  [{tier_label}]")
    if s.get("signer_cn"):
        print(f"  Signer  : {s['signer_cn']}")
    if s.get("expiry"):
        print(f"  Expiry  : {s['expiry']}")
    print(f"  Detail  : {s['detail']}")

    # VirusTotal
    print(f"\n{_bold('── 3. VirusTotal (v3) ' + SEP2[20:])}")
    vt = report["virustotal"]
    if vt.get("error"):
        print(f"  {_c(Fore.YELLOW if _COLOR else '', 'Warning')} : {vt['error']}")
    else:
        found_str = "Yes" if vt["found"] else "No (hash not indexed)"
        mal_color = Fore.RED if _COLOR and vt["malicious"] > 0 else (Fore.GREEN if _COLOR else "")
        print(f"  Indexed  : {found_str}")
        print(f"  Ratio    : {_c(mal_color, vt['detection_ratio'])}  (flagged / total engines)")
        print(f"  Malicious: {vt['malicious']}   Suspicious: {vt.get('suspicious', 0)}")
        print(f"  Score    : {vt.get('community_score', 'N/A')}  (community reputation)")
        if vt.get("permalink"):
            print(f"  Link     : {vt['permalink']}")

    # Whitelist
    print(f"\n{_bold('── 4. Vendor Hash Database ' + SEP2[25:])}")
    wl = report["whitelist_check"]
    if wl["match"]:
        db_status = wl.get("status", "approved")
        col = (
            Fore.GREEN  if _COLOR and db_status == "approved"
            else Fore.RED    if _COLOR and db_status == "blocked"
            else Fore.YELLOW if _COLOR
            else ""
        )
        print(f"  Match  : {_c(col, db_status.upper())} — "
              f"{wl.get('vendor')} / {wl.get('product')} v{wl.get('version')}")
        if wl.get("notes"):
            print(f"  Notes  : {wl['notes']}")
    else:
        print(f"  {_c(Fore.YELLOW if _COLOR else '', 'NO MATCH')} — hash not present in vendor database.")

    # Verdict
    print(f"\n{_bold('── 5. Confidence Verdict ' + SEP2[23:])}")
    v = report["verdict"]
    print(f"  Score   : {v['score']}")
    for r in v["reasons"]:
        print(f"    · {r}")
    for w in v.get("warnings", []):
        print(f"  {_c(Fore.YELLOW if _COLOR else '', '⚠ WARNING')} : {w}")
    print(f"\n  ► {_c(verdict_color, _bold(v['verdict']))}")

    # Case Validation
    cv = report["case_validation"]
    print(f"\n{_bold('── 6. Case Validation Reference ' + SEP2[30:])}")
    gt_col = Fore.GREEN if _COLOR and cv["verdict_category_match"] else (Fore.RED if _COLOR else "")
    print(f"  Ground-truth case : {cv['ground_truth_name']}")
    print(f"  GT SHA-256        : {cv['ground_truth_sha256']}")
    print(f"  GT Verdict        : {cv['ground_truth_verdict']}  (score ≈ {cv['ground_truth_score']})")
    print(f"  This file verdict : {cv['current_verdict']}  (score = {cv['current_score']})")
    match_label = "✓ MATCH" if cv["verdict_category_match"] else "✗ MISMATCH"
    print(f"  Category match    : {_c(gt_col, match_label)}")
    if cv["is_ground_truth_hash"]:
        print(f"  {_c(Fore.GREEN if _COLOR else '', '★ GROUND-TRUTH HASH DETECTED — Validated against Tahakom case study.')}")
    print(f"  Framework conf.   : {cv['framework_confidence']}")

    print(f"\n{_bold(SEP)}\n")


def save_report(report: dict, out_path: Path) -> None:
    """Write the report to a JSON file."""
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    _info(f"Report saved → {out_path}")


# ════════════════════════════════════════════════════════════════════════════
# Self-Validation Mode (--validate-case)
# ════════════════════════════════════════════════════════════════════════════

def run_validate_case(db_path: Path, vt_key: str, vt_delay: int) -> int:
    """
    Print a side-by-side comparison of the framework's expected behaviour
    against the ManageEngine UEMS ground-truth case.

    Does NOT require the actual binary — simulates the pipeline inputs
    directly from the GROUND_TRUTH_CASE constant and the vendor DB.
    """
    gt = GROUND_TRUTH_CASE
    SEP = "═" * 72

    print(f"\n{_bold(SEP)}")
    print(_bold("  SELF-VALIDATION MODE — ManageEngine UEMS Ground-Truth Case"))
    print(_bold(f"  {_PROJECT_TITLE}"))
    print(_bold(SEP))
    print(f"\n  Case    : {gt['name']}")
    print(f"  Date    : {gt['date']}")
    print(f"  Network : {gt['network']}")
    print(f"  VT known: {gt['vt_ratio']}")
    print(f"  Signed  : {'Yes' if gt['signed'] else 'No (Unsigned)'}")
    print()

    # Simulate the signature result (binary is unsigned per ground-truth)
    sim_sig = {
        "status":    "Unsigned",
        "signer_cn": "",
        "expiry":    "",
        "detail":    "Simulated from ground-truth: binary confirmed unsigned.",
        "tier":      2,
    }

    # Simulate a VT result matching the known 1/69 ratio
    sim_vt = {
        "found":           True,
        "detection_ratio": "1/69",
        "malicious":       1,
        "suspicious":      0,
        "total_engines":   69,
        "community_score": 0,
        "permalink":       f"https://www.virustotal.com/gui/file/{gt['sha256']}",
        "error":           None,
    }

    # Load actual DB for whitelist check
    vendor_db = load_vendor_db(db_path)
    whitelist = check_whitelist(gt["sha256"], vendor_db)
    verdict   = compute_verdict(sim_sig, sim_vt, whitelist)
    cv        = build_case_validation(gt["sha256"], verdict)

    # Print side-by-side comparison
    print(_bold("  Indicator          Tool Result            Ground-Truth"))
    print("  " + "─" * 68)
    rows = [
        ("Signature",  sim_sig["status"],                  "Unsigned"),
        ("VT Ratio",   sim_vt["detection_ratio"],           gt["vt_ratio"].split()[0]),
        ("DB Status",  whitelist.get("status") or "miss",  "pending_verification"),
        ("Score",      str(verdict["score"]),               str(gt["expected_score"])),
        ("Verdict",    verdict["verdict"],                  gt["final_verdict"]),
    ]
    all_match = True
    for label, tool_val, gt_val in rows:
        # Loose match (normalise case)
        match = tool_val.strip().lower() == gt_val.strip().lower()
        if not match:
            # Accept "Low Confidence" matching as long as both are "low" category
            if (("low" in tool_val.lower() or "pending" in tool_val.lower()) and
                    ("low" in gt_val.lower() or "pending" in gt_val.lower())):
                match = True
        sym  = _c(Fore.GREEN if _COLOR else "", "✓") if match else _c(Fore.RED if _COLOR else "", "✗")
        if not match:
            all_match = False
        print(f"  {label:<18} {_short(tool_val):<26} {_short(gt_val):<26} {sym}")

    print(f"\n  Tool verdict (full) : {verdict['verdict']}")
    print(f"  GT verdict (full)   : {gt['final_verdict']}")

    print()
    if all_match:
        print(
            _c(Fore.GREEN if _COLOR else "", _bold(
                "  VALIDATION PASSED — All indicators match the ground-truth case. "
                "Framework is correctly calibrated."
            ))
        )
    else:
        print(
            _c(Fore.RED if _COLOR else "", _bold(
                "  VALIDATION FAILED — One or more indicators diverge from ground-truth. "
                "Review scoring weights or vendor_hashes.json."
            ))
        )

    print()
    print(f"  Recommendation: {gt['recommendation']}")
    print(f"\n{_bold(SEP)}\n")

    return 0 if all_match else 1


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=_TOOL_NAME,
        description=(
            f"{_TOOL_NAME} v{_TOOL_VERSION}\n"
            f"{_PROJECT_TITLE}\n"
            f"{_INSTITUTION}\n\n"
            "Validates suspicious RMM installer binaries through a six-stage "
            "evidence pipeline and outputs a calibrated SOC analyst verdict."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  Low Confidence (clean or insufficient evidence)\n"
            "  1  Medium Confidence (escalate for analyst review)\n"
            "  2  High Confidence (malicious — trigger incident response)\n"
            "  3  Fatal input error (file not found, invalid arguments)\n"
        ),
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        nargs="?",
        help="Path to the suspicious binary (e.g. 'InstallShield Setup.exe').",
    )
    parser.add_argument(
        "--vt-key",
        metavar="API_KEY",
        default=os.environ.get("VT_API_KEY", ""),
        help=(
            "VirusTotal v3 API key. "
            "Alternatively set the VT_API_KEY environment variable. "
            "Omit to run in offline mode (reduced accuracy)."
        ),
    )
    parser.add_argument(
        "--db",
        metavar="DB_PATH",
        default=str(DEFAULT_DB_PATH),
        help=f"Vendor hash JSON database path. Default: {DEFAULT_DB_PATH}",
    )
    parser.add_argument(
        "--out",
        metavar="REPORT_PATH",
        default="",
        help="Optional path to write the JSON report (e.g. --out report.json).",
    )
    parser.add_argument(
        "--vt-delay",
        metavar="SECONDS",
        type=int,
        default=VT_PROACTIVE_DELAY,
        help=(
            f"Proactive delay between VT requests in seconds "
            f"(default: {VT_PROACTIVE_DELAY}; free tier safe minimum: 15)."
        ),
    )
    parser.add_argument(
        "--add-to-db",
        metavar="SHA256:VENDOR:PRODUCT",
        default="",
        help=(
            "Append a new hash to the vendor database and exit. "
            "Format: <64-hex-sha256>:<vendor name>:<product name>  "
            "Status defaults to 'pending_verification'."
        ),
    )
    parser.add_argument(
        "--validate-case",
        action="store_true",
        help=(
            "Run self-validation against the ManageEngine UEMS ground-truth "
            "case and print a side-by-side comparison. No FILE argument needed."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{_TOOL_NAME} v{_TOOL_VERSION}",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress [INFO] progress messages.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    global _COLOR, _QUIET
    if args.no_color:
        _COLOR = False
    _QUIET = args.quiet

    # ── --add-to-db mode ──────────────────────────────────────────────────
    if args.add_to_db:
        parts = args.add_to_db.split(":", 2)
        if len(parts) != 3:
            _err("--add-to-db requires format  sha256:vendor:product")
            return 3
        sha256_new, vendor_new, product_new = (p.strip() for p in parts)
        try:
            add_hash_to_db(Path(args.db), sha256_new, vendor_new, product_new)
        except ValueError as exc:
            _err(str(exc))
            return 3
        except OSError as exc:
            _err(f"Could not write to DB: {exc}")
            return 3
        return 0

    # ── --validate-case mode ──────────────────────────────────────────────
    if args.validate_case:
        return run_validate_case(Path(args.db), args.vt_key, args.vt_delay)

    # ── Normal analysis mode ──────────────────────────────────────────────
    if not args.file:
        _err("FILE argument is required (or use --validate-case / --add-to-db).")
        return 3

    file_path = Path(args.file)
    if not file_path.exists():
        _err(f"File not found: '{file_path}'")
        return 3
    if not file_path.is_file():
        _err(f"Path is not a regular file: '{file_path}'")
        return 3

    _info(f"Analysing: {file_path.resolve()}")

    # 1 — Hashing
    _info("Stage 1/6 — Computing cryptographic hashes…")
    try:
        hashes = compute_hashes(file_path)
    except (OSError, PermissionError) as exc:
        _err(f"Cannot read file: {exc}")
        return 3

    # 2 — Signature
    _info("Stage 2/6 — Verifying digital signature…")
    sig = check_signature(file_path)
    if sig["tier"] == 1:
        _info("  Tier-1 (full Authenticode digest verification) used.")
    elif sig["tier"] == 2 and sig["status"] != "Not a PE":
        _warn("  Tier-2 (structural check only). pip install asn1crypto cryptography for full verification.")

    # 3 — VirusTotal
    _info("Stage 3/6 — Querying VirusTotal API…")
    if not args.vt_key:
        _warn("No VT API key — running in OFFLINE MODE. Verdict accuracy is reduced.")
    vt = query_virustotal(hashes["sha256"], args.vt_key, args.vt_delay)

    # 4 — Whitelist
    _info("Stage 4/6 — Checking vendor hash database…")
    vendor_db = load_vendor_db(Path(args.db))
    whitelist = check_whitelist(hashes["sha256"], vendor_db)

    # 5 — Verdict
    _info("Stage 5/6 — Computing confidence verdict…")
    verdict = compute_verdict(sig, vt, whitelist)

    # 6 — Report
    _info("Stage 6/6 — Generating report…")
    case_validation = build_case_validation(hashes["sha256"], verdict)
    report = build_report(file_path, hashes, sig, vt, whitelist, verdict, case_validation)
    print_report(report, verdict["color"])

    if args.out:
        try:
            save_report(report, Path(args.out))
        except OSError as exc:
            _warn(f"Could not write report file: {exc}")

    # Exit code for SOAR/CI integration
    score = verdict["score"]
    if score >= VERDICT_THRESHOLDS["high"]:
        return 2
    if score >= VERDICT_THRESHOLDS["medium"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
