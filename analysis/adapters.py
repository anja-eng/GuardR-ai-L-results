import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional

REFS_DIR = Path(__file__).parent.parent / "refs"


@dataclass
class NormalizedThreat:
    component: str
    threat_category: str
    threat_description: str
    linked_assets: list = field(default_factory=list)
    atm_technique_id: Optional[str] = None
    risk_value: Optional[int] = None
    risk_treatment: Optional[str] = None
    has_goal: bool = False
    goal_statement: Optional[str] = None


def _load_name_to_id() -> dict:
    path = REFS_DIR / "asset_name_to_id.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


_NAME_TO_ID = _load_name_to_id()
_UNMATCHED_LOG = [] 


def _resolve_asset(name: str) -> str:
    resolved = _NAME_TO_ID.get(name.strip().lower())
    if resolved is None:
        _UNMATCHED_LOG.append(name)
        return name
    return resolved


def _normalize_linked_assets(raw_assets: Any, config_name: str) -> list[str]:
    if raw_assets is None:
        return []
    if not isinstance(raw_assets, list):
        raise TypeError(f"{config_name}: linked_assets must be a list, got {type(raw_assets).__name__}")

    normalized_assets: list[str] = []
    for index, asset in enumerate(raw_assets, start=1):
        if isinstance(asset, str):
            normalized_assets.append(_resolve_asset(asset))
            continue
        if isinstance(asset, dict):
            asset_id = asset.get("asset_id")
            if not isinstance(asset_id, str) or not asset_id.strip():
                raise TypeError(
                    f"{config_name}: linked_assets[{index}] is a dict but has no non-empty asset_id"
                )
            normalized_assets.append(asset_id.strip())
            continue
        raise TypeError(
            f"{config_name}: linked_assets[{index}] has unexpected type {type(asset).__name__}; "
            + "expected either a string asset name or a dict with asset_id"
        )

    return normalized_assets


def _normalize_flat_threats(raw: dict, config_name: str) -> list[NormalizedThreat]:
    threats = raw.get("threats")
    if not isinstance(threats, list):
        raise TypeError(f"{config_name}: expected top-level 'threats' list")

    out = []
    for index, threat in enumerate(threats, start=1):
        if not isinstance(threat, dict):
            raise TypeError(f"{config_name}: threats[{index}] is not an object")
        goal = threat.get("cybersecurity_goal")
        out.append(NormalizedThreat(
            component=threat.get("component", ""),
            threat_category=threat.get("threat_category", ""),
            threat_description=threat.get("threat_description", ""),
            linked_assets=_normalize_linked_assets(threat.get("linked_assets", []), config_name),
            atm_technique_id=threat.get("atm_technique_id"),
            risk_value=threat.get("risk_value"),
            risk_treatment=threat.get("risk_treatment"),
            has_goal=goal is not None,
            goal_statement=(goal or {}).get("csg_statement") if goal else None,
        ))
    return out


def _normalize_nested_components(raw: dict, config_name: str) -> list[NormalizedThreat]:
    components = raw.get("components")
    if not isinstance(components, dict):
        raise TypeError(f"{config_name}: expected top-level 'components' mapping")

    out = []
    for component_name, threats in components.items():
        if not isinstance(threats, list):
            raise TypeError(f"{config_name}: component bucket '{component_name}' is not a list")
        for index, threat in enumerate(threats, start=1):
            if not isinstance(threat, dict):
                raise TypeError(f"{config_name}: {component_name}[{index}] is not an object")
            risk_assessment = threat.get("risk_assessment") or {}
            goal = threat.get("cybersecurity_goal")
            out.append(NormalizedThreat(
                component=component_name,
                threat_category=threat.get("threat_category", ""),
                threat_description=threat.get("threat_description", ""),
                linked_assets=_normalize_linked_assets(threat.get("linked_assets", []), config_name),
                atm_technique_id=(threat.get("atm_mapping") or {}).get("technique_id"),
                risk_value=risk_assessment.get("risk_value"),
                risk_treatment=risk_assessment.get("risk_treatment"),
                has_goal=goal is not None,
                goal_statement=(goal or {}).get("csg_statement") if goal else None,
            ))
    return out


def normalize_c0(raw: dict) -> list:
    return _normalize_flat_threats(raw, "c_0")


def normalize_c1(raw: dict) -> list:
    if "components" in raw:
        return _normalize_nested_components(raw, "c_1")
    return _normalize_flat_threats(raw, "c_1")


def normalize_c2(raw: dict) -> list:
    if "components" in raw:
        return _normalize_nested_components(raw, "c_2")
    return _normalize_flat_threats(raw, "c_2")


def normalize_c3(raw: dict) -> list:
    return _normalize_nested_components(raw, "c_3")


def normalize_c4(raw: dict) -> list:
    return _normalize_nested_components(raw, "c_4")

ADAPTER_MAP = {
    "c_0": normalize_c0,
    "c_1": normalize_c1,
    "c_2": normalize_c2,
    "c_3": normalize_c3,
    "c_4": normalize_c4,
}
