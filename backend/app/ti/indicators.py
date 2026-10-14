"""Indicator normalisation, defanging, CSV and STIX 2.1 parsing (THREAT_INTELLIGENCE.md §2-§8).

Indicators are inert strings: nothing here resolves, fetches, or evaluates them. The STIX
pattern support is a small tokenizer for single comparisons (optionally OR-ed); every other
construct is reported as unsupported, never evaluated.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MATCHABLE_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "sha256"})
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TLP_BY_MARKING = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}


class IndicatorError(ValueError):
    pass


def refang(value: str) -> str:
    text = value.strip()
    text = re.sub(r"^hxxp(s?)://", r"http\1://", text, flags=re.I)
    text = re.sub(r"^fxp://", "ftp://", text, flags=re.I)
    for fanged, plain in (
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[:]", ":"),
        ("[at]", "@"),
        ("[@]", "@"),
    ):
        text = text.replace(fanged, plain)
    return text


def defang(indicator_type: str, value: str) -> str:
    """Display form for URLs/domains/emails so they are never clickable."""
    if indicator_type in ("url", "domain", "email"):
        text = re.sub(r"^http", "hxxp", value, flags=re.I)
        return text.replace(".", "[.]")
    return value


def normalize(indicator_type: str, value: str) -> str:
    kind = indicator_type.strip().lower()
    raw = refang(str(value))
    if not raw:
        raise IndicatorError("empty value")
    if kind in ("ipv4", "ipv6"):
        if kind == "ipv4" and re.search(r"(^|\.)0\d", raw):
            raise IndicatorError("IPv4 with leading zeros is ambiguous")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise IndicatorError(f"invalid {kind} address") from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if (kind == "ipv4") != (address.version == 4):
            raise IndicatorError(f"value is not an {kind} address")
        return str(address)
    if kind == "domain":
        text = raw.lower().rstrip(".")
        if "*" in text:
            raise IndicatorError("wildcard domains are not supported")
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise IndicatorError("invalid internationalised domain") from exc
        labels = text.split(".")
        if len(labels) < 2 or not all(_DOMAIN_LABEL.match(label) for label in labels):
            raise IndicatorError("invalid domain name")
        return text
    if kind == "url":
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
            raise IndicatorError("URL needs http/https/ftp scheme and a host")
        host = parts.hostname.lower()
        port = parts.port
        default = {"http": 80, "https": 443, "ftp": 21}[parts.scheme.lower()]
        netloc = host if port in (None, default) else f"{host}:{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))
    if kind in HASH_LENGTHS:
        text = raw.lower()
        if len(text) != HASH_LENGTHS[kind] or not _HEX.match(text):
            raise IndicatorError(f"{kind} must be {HASH_LENGTHS[kind]} hex characters")
        return text
    if kind == "email":
        local, sep, domain = raw.rpartition("@")
        if not sep or not local or "." not in domain:
            raise IndicatorError("invalid email address")
        return f"{local}@{domain.lower()}"
    raise IndicatorError(f"unsupported indicator type {indicator_type!r}")


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise IndicatorError(f"invalid timestamp {str(value)[:40]!r}") from exc
    if moment.tzinfo is None:
        raise IndicatorError("timestamps must include a timezone")
    return moment.astimezone(UTC)


@dataclass
class ParsedIndicator:
    indicator_type: str
    value_raw: str
    value_normalized: str
    confidence: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    revoked: bool = False
    description: str | None = None
    tlp: str | None = None
    stix_id: str | None = None
    technique_ids: list[str] = field(default_factory=list)


@dataclass
class ParseReport:
    indicators: list[ParsedIndicator] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    unsupported_patterns: list[dict[str, Any]] = field(default_factory=list)
    received: int = 0


_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _confidence(value: Any) -> int | None:
    if value in (None, ""):
        return None
    number = int(float(value))
    if not 0 <= number <= 100:
        raise IndicatorError("confidence must be 0-100")
    return number


def parse_csv(data: bytes) -> ParseReport:
    report = ParseReport()
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    required = {"indicator_type", "value"}
    if not reader.fieldnames or not required <= {f.strip() for f in reader.fieldnames}:
        raise IndicatorError("CSV needs indicator_type and value columns")
    for number, raw_row in enumerate(reader, start=1):
        report.received += 1
        row = {k.strip(): (v or "").strip() for k, v in raw_row.items() if k}
        try:
            kind = row["indicator_type"].lower()
            techniques = [
                t.strip().upper() for t in row.get("technique_ids", "").split(";") if t.strip()
            ]
            bad = [t for t in techniques if not _TECHNIQUE.match(t)]
            if bad:
                raise IndicatorError(f"invalid ATT&CK technique ids {bad}")
            report.indicators.append(
                ParsedIndicator(
                    indicator_type=kind,
                    value_raw=row["value"][:2048],
                    value_normalized=normalize(kind, row["value"]),
                    confidence=_confidence(row.get("confidence")),
                    first_seen=_parse_time(row.get("first_seen")),
                    last_seen=_parse_time(row.get("last_seen")),
                    valid_until=_parse_time(row.get("valid_until")),
                    description=(row.get("description") or None),
                    tlp=(row.get("tlp") or None),
                    technique_ids=techniques,
                )
            )
        except (IndicatorError, ValueError, KeyError) as exc:
            report.rejected.append({"row": number, "reason": str(exc)[:200]})
    return report


# --- STIX 2.1 ------------------------------------------------------------------------------------

STIX_PATHS = {
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:hashes.'sha-256'": "sha256",
    "file:hashes.sha256": "sha256",
    "file:hashes.'sha-1'": "sha1",
    "file:hashes.sha1": "sha1",
    "file:hashes.md5": "md5",
    "file:hashes.'md5'": "md5",
}
_COMPARISON = re.compile(
    r"^\s*\[\s*([a-z0-9-]+:[a-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]\s*$", re.I
)
_UNSUPPORTED_TOKENS = re.compile(
    r"\b(AND|FOLLOWEDBY|MATCHES|LIKE|ISSUBSET|ISSUPERSET|IN|"
    r"WITHIN|START|STOP|REPEATS|NOT)\b|!=|<|>"
)


def parse_pattern(pattern: str) -> list[tuple[str, str]] | str:
    """Returns [(indicator_type, value), ...] or an 'unsupported: reason' string."""
    if len(pattern) > 4096:
        return "unsupported: pattern too long"
    outside_quotes = re.sub(r"'(?:[^'\\]|\\.)*'", "''", pattern)
    if _UNSUPPORTED_TOKENS.search(outside_quotes):
        return "unsupported: only '=' comparisons joined by OR are supported"
    parts = re.split(r"\]\s+OR\s+\[", pattern.strip())
    if len(parts) > 1:
        parts = [p if p.startswith("[") else "[" + p for p in parts]
        parts = [p if p.rstrip().endswith("]") else p + "]" for p in parts]
    result = []
    for part in parts:
        match = _COMPARISON.match(part)
        if not match:
            return "unsupported: not a simple comparison"
        path = match.group(1).lower().replace('"', "'")
        kind = STIX_PATHS.get(path)
        if kind is None:
            return f"unsupported: object path {match.group(1)}"
        result.append((kind, match.group(2).replace("\\'", "'").replace("\\\\", "\\")))
    return result


def parse_stix_bundle(data: bytes) -> ParseReport:
    try:
        bundle = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IndicatorError("not a JSON document") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise IndicatorError("expected a STIX 2.1 bundle (type = 'bundle')")
    objects = [o for o in bundle.get("objects", []) if isinstance(o, dict)]
    attack_ids = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack" and _TECHNIQUE.match(
                    str(ref.get("external_id", ""))
                ):
                    attack_ids[obj.get("id")] = ref["external_id"]
    techniques_for: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "indicates":
            tid = attack_ids.get(obj.get("target_ref"))
            if tid:
                techniques_for.setdefault(str(obj.get("source_ref")), []).append(tid)
    report = ParseReport()
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        report.received += 1
        stix_id = str(obj.get("id", ""))[:256]
        if obj.get("pattern_type", "stix") != "stix":
            report.unsupported_patterns.append(
                {"stix_id": stix_id, "reason": "non-STIX pattern type"}
            )
            continue
        parsed = parse_pattern(str(obj.get("pattern", "")))
        if isinstance(parsed, str):
            report.unsupported_patterns.append({"stix_id": stix_id, "reason": parsed})
            continue
        markings = obj.get("object_marking_refs") or []
        tlp = next((TLP_BY_MARKING[m] for m in markings if m in TLP_BY_MARKING), None)
        for kind, value in parsed:
            try:
                report.indicators.append(
                    ParsedIndicator(
                        indicator_type=kind,
                        value_raw=value[:2048],
                        value_normalized=normalize(kind, value),
                        confidence=_confidence(obj.get("confidence")),
                        first_seen=_parse_time(obj.get("created")),
                        last_seen=_parse_time(obj.get("modified")),
                        valid_from=_parse_time(obj.get("valid_from")),
                        valid_until=_parse_time(obj.get("valid_until")),
                        revoked=bool(obj.get("revoked", False)),
                        description=(
                            str(obj["description"])[:2000] if obj.get("description") else None
                        ),
                        tlp=tlp,
                        stix_id=stix_id,
                        technique_ids=sorted(set(techniques_for.get(stix_id, []))),
                    )
                )
            except (IndicatorError, ValueError) as exc:
                report.rejected.append({"stix_id": stix_id, "reason": str(exc)[:200]})
    return report


# --- ATT&CK --------------------------------------------------------------------------------------


@dataclass
class TechniqueRecord:
    technique_id: str
    stix_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_technique_id: str | None
    deprecated: bool
    revoked: bool
    url: str | None


def parse_attack_bundle(data: bytes) -> tuple[list[TechniqueRecord], str | None]:
    try:
        bundle = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IndicatorError("not a JSON document") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise IndicatorError("expected a STIX bundle")
    version = None
    records = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version")) if obj.get("x_mitre_version") else version
        if obj.get("type") != "attack-pattern":
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", []) or []
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ref or not _TECHNIQUE.match(str(ref.get("external_id", ""))):
            continue
        tid = ref["external_id"]
        records.append(
            TechniqueRecord(
                technique_id=tid,
                stix_id=str(obj.get("id")),
                name=str(obj.get("name", ""))[:500],
                tactics=sorted(
                    {
                        str(p.get("phase_name"))
                        for p in obj.get("kill_chain_phases", []) or []
                        if p.get("kill_chain_name") == "mitre-attack"
                    }
                ),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", "." in tid)),
                parent_technique_id=tid.split(".")[0] if "." in tid else None,
                deprecated=bool(obj.get("x_mitre_deprecated", False)),
                revoked=bool(obj.get("revoked", False)),
                url=str(ref.get("url"))[:500] if ref.get("url") else None,
            )
        )
    return records, version
