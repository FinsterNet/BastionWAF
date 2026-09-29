"""
Multi-Stage Request Normalization Layer (Layer 1 Specification).
Performs bounded recursive decoding, HTML entity unescaping, Base64 detection & decoding,
Unicode NFKC normalization, comment stripping, and null-byte removal.
Preserves both original raw strings and normalized canonical representations for audit logging.
"""

import base64
from dataclasses import dataclass, field
import html
import re
import string
from typing import Dict, Iterator, List, Optional, Tuple, Union
import unicodedata
from urllib.parse import unquote_plus

MAX_DECODE_ITERATIONS = 5
SCANNED_HEADERS: Tuple[str, ...] = ("user-agent", "referer", "cookie", "x-forwarded-for", "origin", "authorization")

PRINTABLE_CHARS = set(string.printable)


def strip_null_bytes(val: str) -> str:
    """Removes null bytes from a string."""
    return val.replace("\x00", "") if val else ""


def repeated_url_decode(val: str, max_iterations: int = MAX_DECODE_ITERATIONS) -> str:
    """Repeatedly URL-decodes a string until it is stable or max_iterations reached."""
    if not val:
        return ""
    current = val
    for _ in range(max_iterations):
        next_val = unquote_plus(current)
        if next_val == current:
            break
        current = next_val
    return current



@dataclass
class NormalizedTarget:
    field_label: str
    raw_value: str
    normalized_value: str


@dataclass
class NormalizedRequest:
    """Canonical form of an HTTP request with dual raw and normalized targets."""

    method: str
    path: str
    raw_path: str
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    raw_query_params: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_body: str = ""
    client_ip: str = ""
    targets: List[NormalizedTarget] = field(default_factory=list)

    def iter_values(self) -> Iterator[Tuple[str, str]]:
        """Yield (field_label, normalized_value) for every user-controlled input."""
        for target in self.targets:
            if target.normalized_value:
                yield target.field_label, target.normalized_value

    def iter_raw_values(self) -> Iterator[Tuple[str, str]]:
        """Yield (field_label, raw_value) for audit logging and forensic comparison."""
        for target in self.targets:
            if target.raw_value:
                yield target.field_label, target.raw_value


def is_valid_base64_payload(val: str) -> Optional[str]:
    """
    Check if a string matches base64 pattern and decodes to valid, printable text.
    Avoids false decoding of random short alphanumeric strings.
    """
    val_stripped = val.strip()
    if len(val_stripped) < 8 or len(val_stripped) % 4 != 0:
        return None

    # Base64 charset pattern
    if not re.fullmatch(r"^[A-Za-z0-9+/]+={0,2}$", val_stripped):
        return None

    try:
        decoded_bytes = base64.b64decode(val_stripped, validate=True)
        # Verify result is valid UTF-8/ASCII and mostly printable text
        decoded_str = decoded_bytes.decode("utf-8")
        printable_ratio = sum(1 for c in decoded_str if c in PRINTABLE_CHARS) / len(decoded_str)
        if printable_ratio >= 0.85 and len(decoded_str) >= 4:
            return decoded_str
    except Exception:
        pass
    return None


def single_pass_decode(value: str) -> str:
    """
    Single normalization pass applying:
    1. URL decode
    2. HTML entity unescape
    3. Base64 detection + decode
    4. Unicode NFKC normalization
    5. Null byte and control char removal
    6. SQL / HTML comment stripping
    """
    if not value:
        return ""

    # 1. URL decode
    decoded = unquote_plus(value)

    # 2. HTML entity decode (&#83; -> S, &quot; -> ")
    decoded = html.unescape(decoded)

    # 3. Base64 detection
    b64_res = is_valid_base64_payload(decoded)
    if b64_res:
        decoded = decoded + " " + b64_res

    # 4. Unicode NFKC normalization (collapses full-width and homoglyphs e.g. Ｓ -> S)
    decoded = unicodedata.normalize("NFKC", decoded)

    # 5. Null byte and control character removal
    decoded = decoded.replace("\x00", "").replace("\r", "")

    # 6. Comment stripping (e.g., UNI/**/ON -> UNION, <!-- -->)
    decoded = re.sub(r"/\*!\d*([^*]+)\*/", r" \1 ", decoded)

    def _join_split_kw(m):
        combined = (m.group(1) + m.group(2)).upper()
        if combined in {
            "UNION", "SELECT", "UPDATE", "INSERT", "DELETE", "DROP", "ALTER", "CREATE",
            "FROM", "WHERE", "ORDER", "GROUP", "HAVING", "LIMIT", "TABLE", "DATABASE",
            "SCRIPT", "ALERT", "EXEC", "SLEEP", "BENCHMARK", "EXTRACTVALUE", "UPDATEXML",
            "LOAD_FILE", "OUTFILE", "DUMPFILE", "INFORMATION_SCHEMA", "JAVASCRIPT", "VBSCRIPT"
        }:
            return m.group(1) + m.group(2)
        return m.group(1) + " " + m.group(2)

    decoded = re.sub(r"([a-zA-Z]{2,})/\*.*?\*/([a-zA-Z]{2,})", _join_split_kw, decoded)
    decoded = re.sub(r"/\*.*?\*/", " ", decoded)
    decoded = re.sub(r"<!--.*?-->", " ", decoded)

    return decoded


def recursive_normalize(value: str, max_iterations: int = MAX_DECODE_ITERATIONS) -> str:
    """
    Decode in a bounded loop until stable to defeat nested / double encoding attacks.
    """
    if not value:
        return ""

    current = value
    for _ in range(max_iterations):
        next_val = single_pass_decode(current)
        if next_val == current:
            break
        current = next_val

    # Normalize excessive whitespace
    current = re.sub(r"\s+", " ", current).strip()
    return current


def _parse_query(query_string: str) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    raw_params: Dict[str, List[str]] = {}
    norm_params: Dict[str, List[str]] = {}

    if not query_string:
        return raw_params, norm_params

    for pair in query_string.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        norm_k = recursive_normalize(k)
        norm_v = recursive_normalize(v)

        raw_params.setdefault(k, []).append(v)
        norm_params.setdefault(norm_k, []).append(norm_v)

    return raw_params, norm_params


def normalize_request(
    method: str,
    path: str,
    query_string: str = "",
    headers: Optional[Dict[str, str]] = None,
    body: Union[bytes, str] = b"",
    client_ip: str = "",
) -> NormalizedRequest:
    """
    Constructs a NormalizedRequest containing both canonicalized strings and raw originals.
    """
    # 1. Path
    norm_path = recursive_normalize(path)
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path

    # 2. Query Params
    raw_query_params, norm_query_params = _parse_query(query_string)

    # 3. Headers
    if headers is None:
        raw_headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bastion/1.0"}
    else:
        raw_headers = headers
    norm_headers: Dict[str, str] = {}
    for hk, hv in raw_headers.items():
        norm_headers[hk.lower()] = recursive_normalize(hv)

    # 4. Body
    raw_body_str = ""
    if isinstance(body, bytes):
        try:
            raw_body_str = body.decode("utf-8", errors="replace")
        except Exception:
            raw_body_str = ""
    else:
        raw_body_str = body or ""

    norm_body = recursive_normalize(raw_body_str)

    # Assemble targets list
    targets: List[NormalizedTarget] = []
    targets.append(NormalizedTarget("path", path, norm_path))

    if query_string:
        targets.append(NormalizedTarget("query_string", query_string, recursive_normalize(query_string)))

    for k, vals in norm_query_params.items():
        raw_vals = raw_query_params.get(k, vals)
        for i, v in enumerate(vals):
            raw_v = raw_vals[i] if i < len(raw_vals) else v
            targets.append(NormalizedTarget(f"query:{k}", raw_v, v))

    for hk in SCANNED_HEADERS:
        if hk in norm_headers:
            targets.append(NormalizedTarget(f"header:{hk}", raw_headers.get(hk, norm_headers[hk]), norm_headers[hk]))

    if norm_body:
        targets.append(NormalizedTarget("body", raw_body_str, norm_body))

    return NormalizedRequest(
        method=method.upper(),
        path=norm_path,
        raw_path=path,
        query_params=norm_query_params,
        raw_query_params=raw_query_params,
        headers=norm_headers,
        raw_headers=raw_headers,
        body=norm_body,
        raw_body=raw_body_str,
        client_ip=client_ip,
        targets=targets,
    )
