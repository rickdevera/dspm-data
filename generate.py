"""
generate.py - Config-driven simulation orchestrator.

Usage:
    python3 generate.py                                # Default (config.json)
    python3 generate.py --config configs/fintech.json  # Alternate company
    python3 generate.py --quick                        # 7-day test run
    python3 generate.py --list-configs                 # Show available configs
"""

import json, argparse, os, sys

# Ensures modules resolve from this file's directory
# regardless of where the script is invoked from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timedelta
from config_loader import load_config, validate_config, get_company, get_simulation_settings, get_datastores, get_iam_roles, get_departments
from users import generate_users, inject_departed_users, inject_service_accounts
from activity import simulate_activity
from scenarios import run_all_scenarios

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "configs")

def write_json(filename, data):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

def list_configs():
    print(f"\nAvailable configurations:")
    print(f"  config.json  (default — Meridian Health Analytics / healthcare)")
    if os.path.exists(CONFIGS_DIR):
        for f in sorted(os.listdir(CONFIGS_DIR)):
            if f.endswith(".json"):
                path = os.path.join(CONFIGS_DIR, f)
                try:
                    with open(path) as fh:
                        c = json.load(fh)
                    name = c.get("company", {}).get("name", "unknown")
                    industry = c.get("company", {}).get("industry", "unknown")
                    dept_total = sum(d.get("headcount", 0) for d in c.get("departments", {}).values())
                    print(f"  configs/{f:<25} {name} | {industry} | ~{dept_total} users")
                except Exception:
                    print(f"  configs/{f}  (could not parse)")
    print(f"\nUsage: python3 generate.py --config configs/fintech.json\n")

def run(config_path=None, quick=False):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cfg = load_config(config_path)
    errors = validate_config(cfg)
    if errors:
        print(f"\n[!] Config errors:")
        for e in errors: print(f"    - {e}")
        return

    company     = get_company(cfg)
    sim_cfg     = get_simulation_settings(cfg)
    datastores  = get_datastores(cfg)
    iam_roles   = get_iam_roles(cfg)
    departments = get_departments(cfg)

    sim_end   = datetime.fromisoformat(sim_cfg.get("end_date", "2024-03-31"))
    days      = 7 if quick else sim_cfg.get("days", 90)
    sim_start = sim_end - timedelta(days=days)

    print(f"\n{'='*60}")
    print(f"  {company.get('name')} — DSPM Demo Environment")
    print(f"  Industry:   {company.get('industry', 'unknown')}")
    print(f"  Simulation: {sim_start.date()} → {sim_end.date()} ({days} days)")
    print(f"{'='*60}\n")

    print("[1/4] Building company baseline...")
    users            = generate_users(sim_end, cfg)
    users            = inject_departed_users(users, sim_end, cfg)
    service_accounts = inject_service_accounts(sim_end, cfg)
    all_identities   = users + service_accounts
    print(f"  ✓ {len(all_identities)} identities | {len(datastores)} datastores | {len(iam_roles)} IAM roles")

    write_json("company_baseline.json", {
        "company": company,
        "generated_at": datetime.now().isoformat(),
        "config_used": config_path or "config.json",
        "simulation_period": {"start": sim_start.isoformat(), "end": sim_end.isoformat(), "days": days},
        "identities": {
            "total": len(all_identities),
            "employees": len(users),
            "service_accounts": len(service_accounts),
            "by_department": {d: sum(1 for u in users if u.get("department") == d) for d in departments}
        },
        "users": all_identities,
        "datastores": datastores,
        "iam_roles": iam_roles,
    })

    print("\n[2/4] Simulating activity...")
    events = simulate_activity(all_identities, sim_start, sim_end, cfg)
    print(f"  ✓ {len(events)} baseline events generated")

    print("\n[3/4] Injecting security scenarios...")
    events, findings = run_all_scenarios(all_identities, events, sim_end, cfg)
    scenario_events  = [e for e in events if e.get("scenario")]
    events.sort(key=lambda e: e["timestamp"])
    print(f"  ✓ {len(findings)} findings | {len(scenario_events)} scenario events injected")

    write_json("activity_logs.json", {
        "schema_version": "1.0",
        "schema_note": "Compatible with AWS Security Hub Finding Format (ASFF)",
        "company": company.get("name"),
        "total_events": len(events),
        "events": events
    })

    print("\n[4/4] Writing findings and summary...")
    sh_findings = [{
        **f,
        "ProductArn": f"arn:aws:securityhub:::product/dspm-demo/{company.get('industry','unknown')}",
        "AwsAccountId": "123456789012",
        "CreatedAt": sim_end.isoformat(),
        "UpdatedAt": sim_end.isoformat(),
        "Region": company.get("primary_region", "us-east-1"),
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE"
    } for f in findings]

    write_json("findings.json", {
        "schema_version": "1.0",
        "company": company.get("name"),
        "total_findings": len(sh_findings),
        "by_severity": {s: sum(1 for f in sh_findings if f["severity"] == s) for s in ["CRITICAL","HIGH","MEDIUM","LOW"]},
        "findings": sh_findings
    })

    total_bytes   = sum(e.get("bytes_transferred", 0) for e in events)
    flagged_users = set(e["user_id"] for e in events if e.get("flags"))

    write_json("summary.json", {
        "generated_at": datetime.now().isoformat(),
        "company": company.get("name"),
        "industry": company.get("industry"),
        "config_used": config_path or "config.json",
        "simulation_days": days,
        "identity_summary": {
            "total_identities": len(all_identities),
            "active_employees": sum(1 for u in users if u.get("is_active") and not u.get("is_departed")),
            "orphaned_accounts": sum(1 for u in users if u.get("is_departed")),
            "service_accounts": len(service_accounts),
            "users_without_mfa": sum(1 for u in all_identities if not u.get("mfa_enabled")),
            "users_with_permission_drift": sum(1 for u in users if u.get("has_ghost_role")),
        },
        "datastore_summary": {
            "total_datastores": len(datastores),
            "critical_sensitivity": sum(1 for d in datastores if d.get("sensitivity_level") == "Restricted"),
            "phi_datastores": sum(1 for d in datastores if d.get("category") == "PHI"),
            "pii_datastores": sum(1 for d in datastores if d.get("category") == "PII"),
            "pci_datastores": sum(1 for d in datastores if d.get("category") == "PCI"),
        },
        "activity_summary": {
            "total_events": len(events),
            "scenario_events": len(scenario_events),
            "total_data_transferred_gb": round(total_bytes / 1_000_000_000, 2),
            "unique_flagged_users": len(flagged_users),
        },
        "findings_summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
            "findings": [{"id": f["finding_id"], "severity": f["severity"], "title": f["title"]} for f in findings]
        }
    })

    print(f"\n{'='*60}")
    print(f"  COMPLETE — {company.get('name')}")
    print(f"  Identities: {len(all_identities)} | Events: {len(events):,} | Findings: {len(findings)}")
    print(f"  Explore: python3 query.py summary")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DSPM Demo Environment Generator")
    parser.add_argument("--config",       help="Path to config file (default: config.json)")
    parser.add_argument("--quick",        action="store_true", help="7-day test run")
    parser.add_argument("--list-configs", action="store_true", help="Show available configs")
    args = parser.parse_args()
    if args.list_configs:
        list_configs()
    else:
        run(config_path=args.config, quick=args.quick)
