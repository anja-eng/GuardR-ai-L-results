import json
import glob
import importlib
import statistics
from pathlib import Path
from collections import defaultdict

try:
    mannwhitneyu = importlib.import_module("scipy.stats").mannwhitneyu
    HAVE_SCIPY = True
except ModuleNotFoundError:
    HAVE_SCIPY = False

OUTPUTS_DIR = Path(__file__).parent.parent / "outputs"
RESULTS_DIR = Path(__file__).parent.parent / "results"
GROUNDED_DIR = OUTPUTS_DIR / "c_3" / "grounded"
UNGROUNDED_DIR = OUTPUTS_DIR / "c_3" / "ungrounded"
SUMMARY_PATH = RESULTS_DIR / "rq2_summary.json"


def flatten_with_ids(raw: dict) -> dict:
    result = {}
    for component, threats in raw.get("components", {}).items():
        for i, threat in enumerate(threats):
            ra = threat.get("risk_assessment") or {}
            rv = ra.get("risk_value")
            if rv is not None:
                result[(component, i)] = rv
    return result


def ordered_threat_ids(raw: dict) -> list:
    ids = []
    for component, threats in raw.get("components", {}).items():
        for i, _threat in enumerate(threats):
            ids.append((component, i))
    return ids


def validate_run_shape(raw: dict, run_path: Path) -> None:
    components = raw.get("components")
    if not isinstance(components, dict):
        raise RuntimeError(f"Run file does not contain a valid components mapping: {run_path}")
    for component_name, threats in components.items():
        if not isinstance(threats, list):
            raise RuntimeError(f"Component {component_name} is not a threat list in {run_path}")
        for index, threat in enumerate(threats, start=1):
            if not isinstance(threat, dict):
                raise RuntimeError(f"Threat {component_name}[{index}] is not an object in {run_path}")
            risk_assessment = threat.get("risk_assessment")
            if not isinstance(risk_assessment, dict):
                raise RuntimeError(f"Threat {component_name}[{index}] is missing risk_assessment in {run_path}")
            if risk_assessment.get("risk_value") is None:
                raise RuntimeError(f"Threat {component_name}[{index}] is missing risk_assessment.risk_value in {run_path}")


def load_condition(condition_dir: Path) -> list:
    run_paths = sorted(glob.glob(str(condition_dir / "run_*.json")))
    if not run_paths:
        print(f"WARNING: no runs found in {condition_dir}")
        return []
    runs = []
    reference_ids = None
    for p in run_paths:
        raw = json.loads(Path(p).read_text())
        run_path = Path(p)
        validate_run_shape(raw, run_path)
        run_ids = ordered_threat_ids(raw)
        if reference_ids is None:
            reference_ids = run_ids
        elif run_ids != reference_ids:
            raise RuntimeError(
                f"Threat identity/order drift detected in {run_path}. "
                + "All runs within a condition must preserve identical component and list ordering."
            )
        runs.append(flatten_with_ids(raw))
    print(f"{condition_dir.name}: {len(runs)} runs loaded")
    return runs


def compare_conditions(grounded_runs: list, ungrounded_runs: list) -> dict:
    grounded_ids = set().union(*(run.keys() for run in grounded_runs)) if grounded_runs else set()
    ungrounded_ids = set().union(*(run.keys() for run in ungrounded_runs)) if ungrounded_runs else set()
    grounded_order = list(grounded_runs[0].keys()) if grounded_runs else []
    ungrounded_order = list(ungrounded_runs[0].keys()) if ungrounded_runs else []
    return {
        "same_identity_set": grounded_ids == ungrounded_ids,
        "same_identity_order": grounded_order == ungrounded_order,
        "grounded_only": [f"{c}[{i}]" for (c, i) in sorted(grounded_ids - ungrounded_ids)],
        "ungrounded_only": [f"{c}[{i}]" for (c, i) in sorted(ungrounded_ids - grounded_ids)],
    }


def aggregate_distribution(runs: list) -> dict:
    all_values = [v for run in runs for v in run.values()]
    if not all_values:
        return {"mean": None, "pct_high_critical": None, "n": 0}
    return {
        "mean": statistics.mean(all_values),
        "std": statistics.stdev(all_values) if len(all_values) > 1 else 0.0,
        "pct_high_critical": sum(1 for v in all_values if v >= 4) / len(all_values),
        "n": len(all_values),
    }


def per_threat_variance(runs: list) -> dict:
    by_threat = defaultdict(list)
    for run in runs:
        for threat_id, rv in run.items():
            by_threat[threat_id].append(rv)

    per_threat_std = {}
    for threat_id, values in by_threat.items():
        if len(values) > 1:
            per_threat_std[threat_id] = statistics.stdev(values)

    valid_stds = list(per_threat_std.values())
    mean_std = statistics.mean(valid_stds) if valid_stds else None

    n_runs = len(runs)
    incomplete = {tid: len(vals) for tid, vals in by_threat.items() if len(vals) < n_runs}

    return {
        "mean_per_threat_std": mean_std,
        "n_threats_scored": len(valid_stds),
        "n_threats_incomplete": len(incomplete),
        "incomplete_threat_ids": [f"{c}[{i}]" for (c, i) in incomplete],
    }


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    grounded_runs = load_condition(GROUNDED_DIR)
    ungrounded_runs = load_condition(UNGROUNDED_DIR)

    if not grounded_runs or not ungrounded_runs:
        print("Cannot compare - one or both conditions have no runs yet.")
        return

    alignment = compare_conditions(grounded_runs, ungrounded_runs)
    if not alignment["same_identity_set"] or not alignment["same_identity_order"]:
        raise RuntimeError(
            "Grounded and ungrounded runs are not aligned by threat identity/order. "
            + json.dumps(alignment, indent=2)
        )

    grounded_dist = aggregate_distribution(grounded_runs)
    ungrounded_dist = aggregate_distribution(ungrounded_runs)

    grounded_var = per_threat_variance(grounded_runs)
    ungrounded_var = per_threat_variance(ungrounded_runs)

    result = {
        "grounded": {"distribution": grounded_dist, "per_threat_variance": grounded_var},
        "ungrounded": {"distribution": ungrounded_dist, "per_threat_variance": ungrounded_var},
        "alignment": alignment,
        "mean_shift": (
            ungrounded_dist["mean"] - grounded_dist["mean"]
            if grounded_dist["mean"] is not None and ungrounded_dist["mean"] is not None
            else None
        ),
    }

    if HAVE_SCIPY:
        all_grounded_values = [v for run in grounded_runs for v in run.values()]
        all_ungrounded_values = [v for run in ungrounded_runs for v in run.values()]
        if len(all_grounded_values) > 0 and len(all_ungrounded_values) > 0:
            stat, p_value = mannwhitneyu(all_grounded_values, all_ungrounded_values)
            result["mann_whitney_u"] = {"statistic": stat, "p_value": p_value}
    else:
        print("scipy not installed - skipping Mann-Whitney U test "
              "(pip install scipy --break-system-packages if you want it)")

    print(json.dumps(result, indent=2, default=str))
    SUMMARY_PATH.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nSaved: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()