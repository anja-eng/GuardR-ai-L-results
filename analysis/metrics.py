import re
import statistics

EARS_PATTERN = re.compile(
    r"^The .+ shall (ensure|enforce|protect) .+ against .+", re.IGNORECASE
)
DATAFLOW_ID_PATTERN = re.compile(r"\bDF\d+\b")
VALID_STRIDE = {"Spoofing", "Tampering", "Repudiation",
                 "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
VALID_TREATMENT = {"Avoid", "Share", "Retain", "Reduce"}


def atm_recall(threats: list, baseline: set) -> float | None:
    if not baseline:
        return None
    observed = {t.atm_technique_id for t in threats if t.atm_technique_id}
    return len(observed & baseline) / len(baseline)


def atm_hallucination_rate(threats: list, full_catalog_ids: set) -> float | None:
    if not full_catalog_ids:
        return None
    referenced = [t.atm_technique_id for t in threats if t.atm_technique_id]
    if not referenced:
        return 0.0
    invented = [tid for tid in referenced if tid not in full_catalog_ids]
    return len(invented) / len(referenced)


def structural_asset_coverage(threats: list, all_asset_ids: set) -> float | None:
    if not all_asset_ids:
        return None
    covered = set()
    for threat_index, threat in enumerate(threats, start=1):
        if not isinstance(threat.linked_assets, list):
            raise TypeError(
                f"Threat {threat_index} linked_assets must be a list, got {type(threat.linked_assets).__name__}"
            )
        for asset_index, asset_id in enumerate(threat.linked_assets, start=1):
            if not isinstance(asset_id, str) or not asset_id.strip():
                raise TypeError(
                    f"Threat {threat_index} linked_assets[{asset_index}] must be a non-empty asset ID string, "
                    + f"got {type(asset_id).__name__}"
                )
            if asset_id in all_asset_ids:
                covered.add(asset_id)

    dataflow_ids = {aid for aid in all_asset_ids if aid.startswith("DF")}
    if dataflow_ids:
        all_descriptions = " ".join(t.threat_description or "" for t in threats)
        mentioned_dataflows = set(DATAFLOW_ID_PATTERN.findall(all_descriptions))
        covered |= (mentioned_dataflows & dataflow_ids)

    return len(covered) / len(all_asset_ids)


def stride_category_validity(threats: list) -> float:
    if not threats:
        return 0.0
    ok = sum(1 for t in threats if t.threat_category in VALID_STRIDE)
    return ok / len(threats)


def treatment_validity(threats: list) -> float:
    rated = [t for t in threats if t.risk_treatment]
    if not rated:
        return 0.0
    return sum(1 for t in rated if t.risk_treatment in VALID_TREATMENT) / len(rated)


def treatment_distribution(threats: list) -> dict:
    from collections import Counter
    return dict(Counter(t.risk_treatment for t in threats if t.risk_treatment))


def risk_distribution(threats: list) -> dict:
    vals = [t.risk_value for t in threats if isinstance(t.risk_value, int)]
    if not vals:
        return {"mean": None, "pct_high_critical": None, "n": 0}
    return {
        "mean": statistics.mean(vals),
        "pct_high_critical": sum(1 for v in vals if v >= 4) / len(vals),
        "n": len(vals),
    }


def ears_conformance_rate(threats: list) -> float:
    goal_threats = [t for t in threats if t.has_goal]
    if not goal_threats:
        return 0.0
    ok = sum(1 for t in goal_threats if t.goal_statement and EARS_PATTERN.match(t.goal_statement))
    return ok / len(goal_threats)


def score_goals(goals: list) -> dict:
    n = len(goals)
    if n == 0:
        return {
            "goal_count": 0,
            "goal_ears_conformance": None,
            "goal_traceability_completeness": None,
        }

    ears_ok = sum(
        1 for g in goals
        if g.get("csg_statement") and EARS_PATTERN.match(g["csg_statement"])
    )

    def is_traceable(g: dict) -> bool:
        tm = g.get("traceability_matrix") or {}
        return bool(
            tm.get("linked_asset_ids")
            and tm.get("linked_atm_technique")
            and tm.get("linked_stride_category")
            and tm.get("unmitigated_risk_value") is not None
        )

    traceable_ok = sum(1 for g in goals if is_traceable(g))

    return {
        "goal_count": n,
        "goal_ears_conformance": ears_ok / n,
        "goal_traceability_completeness": traceable_ok / n,
    }


def score_run(threats: list, atm_baseline: set, full_catalog_ids: set, all_asset_ids: set) -> dict:
    rd = risk_distribution(threats)
    return {
        "threat_count": len(threats),
        "atm_recall": atm_recall(threats, atm_baseline),
        "atm_hallucination_rate": atm_hallucination_rate(threats, full_catalog_ids),
        "structural_coverage": structural_asset_coverage(threats, all_asset_ids),
        "stride_validity": stride_category_validity(threats),
        "treatment_validity": treatment_validity(threats),
        "treatment_distribution": treatment_distribution(threats),
        "mean_risk_value": rd["mean"],
        "pct_high_critical": rd["pct_high_critical"],
        "ears_conformance": ears_conformance_rate(threats),
    }
