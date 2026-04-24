"""
query.py
CLI for exploring the generated demo environment.
Designed to show a reviewer the data is rich and consistent.

Usage:
    python3 query.py findings                    # All findings
    python3 query.py findings --severity CRITICAL
    python3 query.py user <username>             # User profile + activity
    python3 query.py datastore <id>              # Datastore access summary
    python3 query.py summary                     # Environment overview
    python3 query.py timeline <user_id>          # 90-day activity timeline
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import json
import argparse
import os
from datetime import datetime
from collections import defaultdict

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def load(filename):
    path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(path):
        print(f"[!] Output not found: {path}")
        print(f"    Run: python3 generate.py first")
        exit(1)
    with open(path) as f:
        return json.load(f)


def cmd_summary(args):
    s = load("summary.json")
    print(f"\n{'='*60}")
    print(f"  {s['company']} — Demo Environment")
    print(f"  Simulation: {s['simulation_days']} days")
    print(f"{'='*60}")

    i = s["identity_summary"]
    print(f"\n  IDENTITIES")
    print(f"  ├── Active employees:       {i['active_employees']}")
    print(f"  ├── Orphaned accounts:      {i['orphaned_accounts']}  ⚠")
    print(f"  ├── Service accounts:       {i['service_accounts']}")
    print(f"  ├── No MFA:                 {i['users_without_mfa']}  ⚠")
    print(f"  └── Permission drift:       {i['users_with_permission_drift']}  ⚠")

    d = s["datastore_summary"]
    print(f"\n  DATASTORES")
    print(f"  ├── Total:                  {d['total_datastores']}")
    print(f"  ├── Critical sensitivity:   {d['critical_sensitivity']}")
    print(f"  ├── PHI:                    {d['phi_datastores']}")
    print(f"  ├── PII:                    {d['pii_datastores']}")
    print(f"  └── PCI:                    {d['pci_datastores']}")

    a = s["activity_summary"]
    print(f"\n  ACTIVITY (90 days)")
    print(f"  ├── Total events:           {a['total_events']:,}")
    print(f"  ├── Scenario events:        {a['scenario_events']}")
    print(f"  ├── Data transferred:       {a['total_data_transferred_gb']} GB")
    print(f"  └── Flagged users:          {a['unique_flagged_users']}")

    f = s["findings_summary"]
    print(f"\n  FINDINGS")
    print(f"  ├── Total:                  {f['total']}")
    print(f"  ├── Critical:               {f['critical']}  🔴")
    print(f"  └── High:                   {f['high']}  🟠")
    print()


def cmd_findings(args):
    data = load("findings.json")
    findings = data["findings"]

    if args.severity:
        findings = [f for f in findings if f["severity"] == args.severity.upper()]

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

    print(f"\n{'='*60}")
    print(f"  DSPM FINDINGS ({len(findings)} total)")
    print(f"{'='*60}\n")

    for f in findings:
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
        print(f"  {sev_icon} [{f['severity']:8}] {f['finding_id']} — {f['title']}")
        print(f"     {f['description'][:120]}...")
        print(f"     MITRE: {f.get('mitre_technique', 'N/A')}")
        print(f"     Signals: {len(f.get('detection_signals', []))} | Events: {f.get('event_count', 0)}")
        if f.get("compliance_impact"):
            print(f"     Compliance: {', '.join(f['compliance_impact'])}")
        print(f"     → {f.get('recommended_action', '')[:100]}")
        print()


def cmd_user(args):
    baseline = load("company_baseline.json")
    logs = load("activity_logs.json")

    username = args.username.lower()
    user = next((u for u in baseline["users"]
                 if u.get("username", "").lower() == username
                 or u.get("user_id", "").lower() == username), None)

    if not user:
        print(f"[!] User not found: {args.username}")
        print(f"    Try: python3 query.py list-users")
        return

    print(f"\n{'='*60}")
    print(f"  USER PROFILE: {user.get('full_name', 'Unknown')}")
    print(f"{'='*60}")
    print(f"  ID:           {user['user_id']}")
    print(f"  Username:     {user.get('username')}")
    print(f"  Department:   {user.get('department')}")
    print(f"  Title:        {user.get('title')}")
    print(f"  Hire date:    {user.get('hire_date', 'unknown')[:10]}")
    print(f"  Tenure:       {user.get('tenure_days', 0)} days")
    print(f"  MFA:          {'✓ Enabled' if user.get('mfa_enabled') else '✗ DISABLED'}")
    print(f"  Active:       {'✓ Yes' if user.get('is_active') else '✗ No'}")

    if user.get("is_departed"):
        print(f"  ⚠ DEPARTED:  {user.get('departure_date', 'unknown')[:10]} — account still active!")

    print(f"\n  IAM ROLES")
    print(f"  Current:      {user.get('current_role')}")
    if user.get("has_ghost_role"):
        print(f"  ⚠ Ghost role detected — permission drift, old role never revoked")
    for r in user.get("role_history", []):
        status = "ACTIVE" if r.get("revoked_date") is None else f"revoked {r['revoked_date'][:10]}"
        flag = f"  ← {r['flag']}" if r.get("flag") else ""
        print(f"  ├── {r['role_id']:30} [{status}]{flag}")

    # Activity summary
    user_events = [e for e in logs["events"] if e.get("user_id") == user["user_id"]]
    flagged = [e for e in user_events if e.get("flags")]

    print(f"\n  ACTIVITY SUMMARY")
    print(f"  Total events:   {len(user_events)}")
    print(f"  Flagged events: {len(flagged)}")

    if user_events:
        total_bytes = sum(e.get("bytes_transferred", 0) for e in user_events)
        print(f"  Data accessed:  {round(total_bytes/1_000_000, 1)} MB")

        ds_counts = defaultdict(int)
        for e in user_events:
            ds_counts[e.get("datastore_id")] += 1
        print(f"\n  DATASTORE ACCESS")
        for ds_id, count in sorted(ds_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"  ├── {ds_id:35} {count:4} events")

    if flagged:
        print(f"\n  ⚠ FLAGS DETECTED")
        flag_types = defaultdict(int)
        for e in flagged:
            for flag in e.get("flags", []):
                flag_types[flag] += 1
        for flag, count in sorted(flag_types.items(), key=lambda x: -x[1]):
            print(f"  ├── {flag:35} {count:4} events")
    print()


def cmd_datastore(args):
    baseline = load("company_baseline.json")
    logs = load("activity_logs.json")

    ds_id = args.datastore_id
    ds = next((d for d in baseline["datastores"] if d["id"] == ds_id), None)

    if not ds:
        available = [d["id"] for d in baseline["datastores"]]
        print(f"[!] Datastore not found: {ds_id}")
        print(f"    Available: {', '.join(available)}")
        return

    print(f"\n{'='*60}")
    print(f"  DATASTORE: {ds['name']}")
    print(f"{'='*60}")
    print(f"  ID:             {ds['id']}")
    print(f"  Type:           {ds['type']}")
    print(f"  Classification: {ds['classification']}  ← sensitivity label")
    print(f"  Sensitivity:    {ds.get('sensitivity_level', ds.get('sensitivity', 'unknown')).upper()}")
    print(f"  Region:         {ds['region']}")
    print(f"  Est. records:   {ds['row_estimate']:,}")
    print(f"  Contains:       {', '.join(ds.get('actual_data_types', ds.get('contains', [])))}")
    print(f"  Compliance:     {', '.join(ds['compliance']) if ds['compliance'] else 'none'}")
    print(f"  Legitimate access for: {', '.join(ds['legitimate_accessors'])}")

    # Access analysis
    ds_events = [e for e in logs["events"] if e.get("datastore_id") == ds_id]
    flagged = [e for e in ds_events if e.get("flags")]

    print(f"\n  ACCESS SUMMARY (simulation period)")
    print(f"  Total accesses:   {len(ds_events):,}")
    print(f"  Flagged accesses: {len(flagged)}")

    if ds_events:
        total_bytes = sum(e.get("bytes_transferred", 0) for e in ds_events)
        print(f"  Data transferred: {round(total_bytes/1_000_000, 1)} MB")

        # Top accessors
        accessor_counts = defaultdict(lambda: {"count": 0, "bytes": 0, "username": ""})
        for e in ds_events:
            uid = e.get("user_id")
            accessor_counts[uid]["count"] += 1
            accessor_counts[uid]["bytes"] += e.get("bytes_transferred", 0)
            accessor_counts[uid]["username"] = e.get("username", uid)

        print(f"\n  TOP ACCESSORS")
        for uid, stats in sorted(accessor_counts.items(),
                                  key=lambda x: -x[1]["count"])[:8]:
            mb = round(stats["bytes"] / 1_000_000, 1)
            print(f"  ├── {stats['username']:30} {stats['count']:4} events  {mb:8.1f} MB")

    if flagged:
        print(f"\n  ⚠ FLAGGED EVENTS")
        for e in flagged[:5]:
            ts = e["timestamp"][:16]
            print(f"  ├── {ts}  {e['username']:20}  {', '.join(e['flags'])}")
        if len(flagged) > 5:
            print(f"  └── ... and {len(flagged)-5} more")
    print()


def cmd_list_users(args):
    baseline = load("company_baseline.json")
    users = baseline["users"]

    print(f"\n{'='*60}")
    print(f"  ALL IDENTITIES ({len(users)})")
    print(f"{'='*60}")

    for dept in sorted(set(u.get("department", "unknown") for u in users)):
        dept_users = [u for u in users if u.get("department") == dept]
        print(f"\n  [{dept.upper()}]")
        for u in dept_users[:6]:
            flags = []
            if u.get("is_departed"):
                flags.append("ORPHANED")
            if u.get("has_ghost_role"):
                flags.append("DRIFT")
            if not u.get("mfa_enabled"):
                flags.append("NO-MFA")
            flag_str = f"  ⚠ {' '.join(flags)}" if flags else ""
            account_type = "[SVC]" if u.get("account_type") == "service" else "     "
            print(f"  {account_type} {u.get('username', ''):30} {u.get('title', ''):35}{flag_str}")


def cmd_timeline(args):
    logs = load("activity_logs.json")

    user_filter = args.user_id
    events = logs["events"]

    if user_filter:
        events = [e for e in events if e.get("user_id") == user_filter
                  or e.get("username") == user_filter]
        if not events:
            print(f"[!] No events found for: {user_filter}")
            print(f"    Try: python3 query.py list-users")
            return

    print(f"timestamp           username                       action          datastore                            bytes       flags")
    print(f"{'-'*120}")

    for e in events:
        ts = e["timestamp"][:16]
        flags = " ".join(e.get("flags", []))
        print(f"{ts}  {e.get('username',''):30} {e['action']:15} {e['datastore_id']:35} "
              f"{e.get('bytes_transferred', 0):>10,}  {flags}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query the Meridian DSPM demo environment")
    subparsers = parser.add_subparsers(dest="command")

    # summary
    p_summary = subparsers.add_parser("summary", help="Environment overview")
    p_summary.set_defaults(func=cmd_summary)

    # findings
    p_findings = subparsers.add_parser("findings", help="Show security findings")
    p_findings.add_argument("--severity", help="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)")
    p_findings.set_defaults(func=cmd_findings)

    # user
    p_user = subparsers.add_parser("user", help="Show user profile and activity")
    p_user.add_argument("username", help="Username or user_id")
    p_user.set_defaults(func=cmd_user)

    # datastore
    p_ds = subparsers.add_parser("datastore", help="Show datastore access summary")
    p_ds.add_argument("datastore_id", help="Datastore ID (e.g. s3-patient-records)")
    p_ds.set_defaults(func=cmd_datastore)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List all identities")
    p_list.set_defaults(func=cmd_list_users)

    # timeline
    p_timeline = subparsers.add_parser("timeline", help="Show user activity timeline")
    p_timeline.add_argument("user_id", nargs="?", help="Username or user_id (default: most flagged user)")
    p_timeline.set_defaults(func=cmd_timeline)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
