import json
import glob
import statistics
from pathlib import Path
from collections import Counter

import metrics
from adapters import ADAPTER_MAP

CONFIGS = ["c_0", "c_1", "c_2", "c_3", "c_4"]
OUTPUTS_DIR = Path(__file__).parent.parent / "outputs"
REFS_DIR = Path(__file__).parent.parent / "refs"
RESULTS_DIR = Path(__file__).parent.parent / "results"
SUMMARY_PATH = RESULTS_DIR / "summary.json"


def load_reference_sets():
    def load_ids(name):
        path = REFS_DIR / name
        if not path.exists():
            return set()
        return set(json.loads(path.read_text()))

    return {
        "atm_baseline": load_ids("atm_baseline.json"),
        "full_catalog_ids": load_ids("full_atm_ids.json"),
        "all_asset_ids": load_ids("all_asset_ids.json"),
    }


def load_run(config_name: str, path: Path) -> list:
    raw = json.loads(path.read_text())
    adapter = ADAPTER_MAP.get(config_name)
    if adapter is None:
        raise NotImplementedError(f"No adapter registered yet for {config_name}")
    return adapter(raw)


def load_goals_for_run(threats_path: Path) -> list:
    goals_path = threats_path.with_name(threats_path.stem + "_goals.json")
    if not goals_path.exists():
        return []
    raw = json.loads(goals_path.read_text())
    return raw.get("cybersecurity_goals", [])


def aggregate_numeric(rows: list) -> dict:
    if not rows:
        return {}
    keys = [k for k, v in rows[0].items() if isinstance(v, (int, float)) or v is None]
    agg = {}
    for k in keys:
        vals = [r[k] for r in rows if isinstance(r.get(k), (int, float))]
        if not vals:
            agg[k] = {"mean": None, "std": None, "n_available": 0}
            continue
        agg[k] = {
            "mean": statistics.mean(vals),
            "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "n_available": len(vals),
        }
    return agg


def aggregate_categorical(rows: list, field: str) -> dict:
    total = Counter()
    for r in rows:
        total.update(r.get(field, {}))
    return dict(total)


def main():
    refs = load_reference_sets()
    for k, v in refs.items():
        if not v:
            print(f"NOTE: reference set '{k}' not found in {REFS_DIR}/ — "
                  f"dependent metrics will report as None until it's added.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = {}
    for config_name in CONFIGS:
        run_paths = sorted([
            p for p in glob.glob(str(OUTPUTS_DIR / config_name / "run_*.json"))
            if not p.endswith("_goals.json")
        ])
        if not run_paths:
            print(f"[skip] {config_name}: no runs found in {OUTPUTS_DIR / config_name}/")
            continue
        if config_name not in ADAPTER_MAP:
            print(f"[skip] {config_name}: {len(run_paths)} run(s) found, but no adapter implemented yet")
            continue

        rows = []
        for p in run_paths:
            threats = load_run(config_name, Path(p))
            row = metrics.score_run(
                threats, refs["atm_baseline"], refs["full_catalog_ids"], refs["all_asset_ids"]
            )
            if config_name == "c_4":
                goals = load_goals_for_run(Path(p))
                row.update(metrics.score_goals(goals))
            rows.append(row)

        summary[config_name] = {
            "n_runs": len(run_paths),
            **aggregate_numeric(rows),
            "treatment_distribution_total": aggregate_categorical(rows, "treatment_distribution"),
        }
        print(f"[done] {config_name}: {len(run_paths)} run(s) scored")

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nSummary written to {SUMMARY_PATH}")
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
