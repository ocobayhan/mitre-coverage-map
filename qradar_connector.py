from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class QRadarConnectorError(RuntimeError):
    pass


def _first(item: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return default


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("items", "results", "value", "data", "mappings", "rules"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []


def _technique_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        for token in value.replace(";", ",").split(","):
            token = token.strip().upper()
            if token.startswith("T") and token[1:].replace(".", "").isdigit():
                found.add(token)
    elif isinstance(value, list):
        for item in value:
            found.update(_technique_ids(item))
    elif isinstance(value, dict):
        direct = _first(
            value,
            "technique_id",
            "techniqueId",
            "techniqueID",
            "external_id",
            "externalId",
            "id",
        )
        found.update(_technique_ids(direct))
        for key in ("techniques", "mitre_techniques", "mitreTechniques", "mappings"):
            if key in value:
                found.update(_technique_ids(value[key]))
    return found


def normalize_mapping_payload(payload: Any) -> list[dict[str, Any]]:
    """Normalize common Use Case Manager mapping response variants."""
    merged: dict[str, dict[str, Any]] = {}
    for item in _records(payload):
        rule = item.get("rule") if isinstance(item.get("rule"), dict) else item
        native_id = str(
            _first(
                rule,
                "rule_uuid",
                "ruleUUID",
                "rule_id",
                "ruleId",
                "id",
                "uuid",
            )
        ).strip()
        if not native_id:
            continue
        name = str(_first(rule, "rule_name", "ruleName", "name", "title", default=native_id)).strip()
        techniques: set[str] = set()
        for source in (item, rule):
            techniques.update(_technique_ids(source))
            for key in ("techniques", "mitre_mappings", "mitreMappings", "mappings"):
                techniques.update(_technique_ids(source.get(key)))
        custom = _first(rule, "custom", "is_custom", "isCustom", default=None)
        mapping_type = str(_first(rule, "origin", "mapping_type", "mappingType", default="")).lower()
        if custom is True or "custom" in mapping_type:
            origin = "custom"
        elif custom is False or "default" in mapping_type or "ibm" in mapping_type:
            origin = "vendor_builtin"
        else:
            origin = "unknown"
        enabled_raw = _first(rule, "enabled", "is_enabled", "isEnabled", "active", default=True)
        enabled = enabled_raw if isinstance(enabled_raw, bool) else str(enabled_raw).lower() not in {"0", "false", "disabled", "inactive"}
        record = merged.setdefault(
            native_id,
            {
                "native_id": native_id,
                "name": name,
                "origin": origin,
                "enabled": enabled,
                "rule_type": str(_first(rule, "rule_type", "ruleType", "type", default="rule")),
                "severity": str(_first(rule, "severity", "magnitude", default="")),
                "techniques": set(),
                "offense_count": int(_first(rule, "offense_count", "offenseCount", default=0) or 0),
                "last_offense_at": str(_first(rule, "last_offense_at", "lastOffenseAt", default="")),
            },
        )
        record["techniques"].update(techniques)
        if record["name"] == native_id and name != native_id:
            record["name"] = name

    result: list[dict[str, Any]] = []
    for record in merged.values():
        record["techniques"] = sorted(record["techniques"])
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        record["payload_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        result.append(record)
    return sorted(result, key=lambda item: (item["name"].casefold(), item["native_id"]))


class QRadarClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        mappings_path: str,
        *,
        verify_tls: bool = True,
        ca_bundle: str = "",
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.mappings_path = "/" + mappings_path.lstrip("/")
        self.timeout = max(3, min(timeout, 120))
        if verify_tls:
            self.context = ssl.create_default_context(cafile=ca_bundle or None)
        else:
            self.context = ssl._create_unverified_context()

    def get_json(self, path: str) -> Any:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "SEC": self.token, "User-Agent": "SOC-Coverage-Map/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                body = response.read(20 * 1024 * 1024 + 1)
                if len(body) > 20 * 1024 * 1024:
                    raise QRadarConnectorError("QRadar response exceeded 20 MB")
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise QRadarConnectorError(f"QRadar HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise QRadarConnectorError(f"QRadar connection failed: {exc.reason}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise QRadarConnectorError("QRadar returned invalid JSON") from exc

    def test(self) -> dict[str, Any]:
        payload = self.get_json(self.mappings_path)
        records = normalize_mapping_payload(payload)
        return {"ok": True, "mapping_records": len(records)}

    def fetch_detections(self) -> list[dict[str, Any]]:
        return normalize_mapping_payload(self.get_json(self.mappings_path))
