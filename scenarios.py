"""
scenarios.py
Injects specific security scenarios into the baseline activity.
Scenarios are not hardcoded outputs — they're injected behaviors
that interact with the simulation data naturally.

DSPM-relevant scenarios modeled after real Tenable/Cyera findings:
  1. Data exfiltration pattern (pre-departure download spike)
  2. Orphaned account access (departed employee still active)
  3. Anomalous access from foreign IP (possible credential compromise)
  4. Over-permissioned service account (touches data it shouldn't need)
  5. Sensitive data in wrong place (PII found in dev bucket)
  6. Privilege drift access (ghost role used to reach sensitive data)
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import random
import json
from datetime import datetime, timedelta

from activity import generate_source_ip, ACTION_VOLUMES

random.seed(99)  # Different seed from baseline for scenario variety

SCENARIO_REGISTRY = []


def register_scenario(fn):
    SCENARIO_REGISTRY.append(fn)
    return fn


# ─────────────────────────────────────────────────────────────
# SCENARIO 1: Pre-departure data exfiltration pattern
# User leaving in 2 weeks suddenly downloads 40x normal volume
# from customer PII and patient records buckets
# ─────────────────────────────────────────────────────────────
@register_scenario
def scenario_pre_departure_exfil(users, events, sim_end, cfg=None):
    """
    Find a sales or CS user. In the 2 weeks before sim_end,
    inject a spike in large GetObject/CopyObject events against
    the customer PII bucket. Volume is 40x their normal baseline.
    """
    candidates = [u for u in users
                  if u.get("department") in ["sales", "customer_success"]
                  and not u.get("is_departed")
                  and not u.get("account_type") == "service"
                  and u.get("tenure_days", 0) > 180]

    if not candidates:
        return events, []

    target = random.choice(candidates)
    exfil_start = sim_end - timedelta(days=14)
    injected = []

    for day_offset in range(14):
        event_date = exfil_start + timedelta(days=day_offset)
        if event_date.weekday() >= 5:
            continue  # Skip weekends for realism

        # 3-8 large download events per day
        for _ in range(random.randint(3, 8)):
            hour = random.randint(17, 22)   # after hours
            minute = random.randint(0, 59)
            event_time = event_date.replace(hour=hour, minute=minute,
                                             second=random.randint(0, 59))

            action = random.choice(["GetObject", "CopyObject"])
            bytes_out = random.randint(50_000_000, 500_000_000)  # 50MB-500MB

            event = {
                "event_id": f"evt_scen1_{target['user_id']}_{int(event_time.timestamp())}",
                "timestamp": event_time.isoformat(),
                "user_id": target["user_id"],
                "username": target.get("username"),
                "action": action,
                "datastore_id": "s3-customer-pii",
                "datastore_name": "meridian-customer-data-prod",
                "datastore_classification": "PII",
                "bytes_transferred": bytes_out,
                "source_ip": generate_source_ip(target),
                "region": "us-east-1",
                "status": "SUCCESS",
                "flags": ["EXFIL_PATTERN", "VOLUME_ANOMALY"],
                "scenario": "pre_departure_exfiltration"
            }
            injected.append(event)

    finding = {
        "finding_id": "FIND-001",
        "scenario": "pre_departure_exfiltration",
        "severity": "CRITICAL",
        "title": "Suspected Pre-Departure Data Exfiltration",
        "description": (
            f"{target['full_name']} ({target['department']}) showed a 40x spike in data "
            f"downloads from the customer PII datastore in the 14 days prior to simulation end. "
            f"Activity concentrated in evening hours (5pm-10pm), outside normal work pattern."
        ),
        "affected_user": target["user_id"],
        "affected_user_name": target.get("full_name"),
        "affected_datastore": "s3-customer-pii",
        "datastore_classification": "PII",
        "event_count": len(injected),
        "total_bytes": sum(e["bytes_transferred"] for e in injected),
        "detection_signals": [
            "Volume anomaly: 40x baseline download rate",
            "Time anomaly: activity outside normal work hours",
            "Datastore sensitivity: PII classification",
            "Behavioral change: sustained over 14-day period"
        ],
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1537 - Transfer Data to Cloud Account",
        "compliance_impact": ["GDPR Art.33 - Breach notification", "CCPA"],
        "recommended_action": "Suspend account, initiate DLP review, preserve logs for forensics"
    }

    return events + injected, [finding]


# ─────────────────────────────────────────────────────────────
# SCENARIO 2: Orphaned account used post-departure
# Departed employee's account is still active and accessed
# a sensitive datastore after their departure date
# ─────────────────────────────────────────────────────────────
@register_scenario
def scenario_orphaned_account_access(users, events, sim_end, cfg=None):
    """
    Take a departed user. Generate access events AFTER their departure date.
    This is either continued use or credential theft.
    """
    departed = [u for u in users if u.get("is_departed")]
    if not departed:
        return events, []

    target = random.choice(departed)
    departure_date = datetime.fromisoformat(target["departure_date"])
    injected = []

    # 2-5 access events post-departure, spread randomly
    for i in range(random.randint(2, 5)):
        days_after = random.randint(3, 45)
        event_time = departure_date + timedelta(
            days=days_after,
            hours=random.randint(1, 23),
            minutes=random.randint(0, 59)
        )
        if event_time > sim_end:
            continue

        ds_by_id = {d["id"]: d for d in (cfg.get("datastores", []) if cfg else [])}
        sensitive_ids = [d["id"] for d in (cfg.get("datastores", []) if cfg else []) if d.get("classification") in ["PII","PHI","PCI","CONFIDENTIAL"]] or ["s3-customer-pii"]
        ds_id = random.choice(sensitive_ids)
        ds = ds_by_id.get(ds_id)

        event = {
            "event_id": f"evt_scen2_{target['user_id']}_{i}",
            "timestamp": event_time.isoformat(),
            "user_id": target["user_id"],
            "username": target.get("username"),
            "action": "GetObject",
            "datastore_id": ds_id,
            "datastore_name": ds["name"] if ds else ds_id,
            "datastore_classification": ds["classification"] if ds else "UNKNOWN",
            "bytes_transferred": random.randint(100_000, 50_000_000),
            "source_ip": generate_source_ip(target, is_anomalous=(random.random() > 0.5)),
            "region": "us-east-1",
            "status": "SUCCESS",
            "flags": ["ORPHANED_ACCOUNT", "POST_DEPARTURE_ACCESS"],
            "scenario": "orphaned_account_access"
        }
        injected.append(event)

    finding = {
        "finding_id": "FIND-002",
        "scenario": "orphaned_account_access",
        "severity": "HIGH",
        "title": "Active Access by Departed Employee",
        "description": (
            f"{target['full_name']} departed on {target['departure_date']} but their account "
            f"remains active. {len(injected)} access events detected after departure, targeting "
            f"sensitive datastores including PII and employee records."
        ),
        "affected_user": target["user_id"],
        "affected_user_name": target.get("full_name"),
        "departure_date": target["departure_date"],
        "days_since_departure": (sim_end - departure_date).days,
        "event_count": len(injected),
        "detection_signals": [
            "Account active past departure date",
            f"Access {(sim_end - departure_date).days} days post-departure",
            "No offboarding record in identity system",
            "MFA disabled — account potentially compromised"
        ],
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "compliance_impact": ["SOC2 CC6.2 - Logical access removal", "HIPAA § 164.308(a)(3)"],
        "recommended_action": "Immediately disable account, audit all post-departure activity, involve HR and Legal"
    }

    return events + injected, [finding]


# ─────────────────────────────────────────────────────────────
# SCENARIO 3: Credential compromise / foreign IP access
# A normal user suddenly accessing from a foreign IP range
# at an unusual hour, hitting sensitive datastores
# ─────────────────────────────────────────────────────────────
@register_scenario
def scenario_foreign_ip_access(users, events, sim_end, cfg=None):
    """
    Pick a normal employee. For 3-5 days mid-simulation,
    inject access from a foreign IP at unusual hours.
    """
    candidates = [u for u in users
                  if not u.get("is_departed")
                  and not u.get("account_type") == "service"
                  and u.get("department") in ["engineering", "data_science", "finance"]]

    if not candidates:
        return events, []

    target = random.choice(candidates)
    # Incident happens mid-simulation
    incident_start = sim_end - timedelta(days=random.randint(20, 45))
    foreign_ip = f"103.21.244.{random.randint(1, 254)}"
    injected = []

    for day_offset in range(random.randint(3, 5)):
        event_date = incident_start + timedelta(days=day_offset)

        for _ in range(random.randint(2, 6)):
            hour = random.randint(1, 5)  # 1am-5am local time
            event_time = event_date.replace(hour=hour,
                                             minute=random.randint(0, 59),
                                             second=random.randint(0, 59))

            ds_by_id = {d["id"]: d for d in (cfg.get("datastores", []) if cfg else [])}
            critical_ids = [d["id"] for d in (cfg.get("datastores", []) if cfg else []) if d.get("sensitivity") in ["critical","high"]] or ["s3-customer-pii"]
            ds_id = random.choice(critical_ids)
            ds = ds_by_id.get(ds_id)

            event = {
                "event_id": f"evt_scen3_{target['user_id']}_{int(event_time.timestamp())}",
                "timestamp": event_time.isoformat(),
                "user_id": target["user_id"],
                "username": target.get("username"),
                "action": random.choice(["GetObject", "SELECT", "ListBucket"]),
                "datastore_id": ds_id,
                "datastore_name": ds["name"] if ds else ds_id,
                "datastore_classification": ds["classification"] if ds else "UNKNOWN",
                "bytes_transferred": random.randint(5_000_000, 100_000_000),
                "source_ip": foreign_ip,
                "region": "us-east-1",
                "status": "SUCCESS",
                "flags": ["FOREIGN_IP", "TIME_ANOMALY", "CREDENTIAL_RISK"],
                "scenario": "foreign_ip_credential_compromise"
            }
            injected.append(event)

    finding = {
        "finding_id": "FIND-003",
        "scenario": "foreign_ip_credential_compromise",
        "severity": "CRITICAL",
        "title": "Possible Credential Compromise — Foreign IP Access to Sensitive Data",
        "description": (
            f"{target['full_name']} ({target['department']}) accessed critical datastores "
            f"from IP {foreign_ip} (foreign range) between 1am-5am over {day_offset+1} days. "
            f"Normal access pattern is {target['work_pattern']} from {target['home_ip']}."
        ),
        "affected_user": target["user_id"],
        "affected_user_name": target.get("full_name"),
        "suspicious_ip": foreign_ip,
        "normal_ip": target.get("home_ip"),
        "event_count": len(injected),
        "detection_signals": [
            f"IP deviation: normal {target.get('home_ip')} vs suspicious {foreign_ip}",
            "Time anomaly: 1am-5am activity, outside all work patterns",
            "Geolocation: foreign IP range, not VPN",
            "Data sensitivity: PHI and PCI datastores accessed",
            "No travel notice logged in HR system"
        ],
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1078.004 - Cloud Accounts",
        "compliance_impact": ["HIPAA Breach Rule", "PCI DSS Req 10.6"],
        "recommended_action": "Force password reset, revoke active sessions, enable step-up MFA, review accessed records"
    }

    return events + injected, [finding]


# ─────────────────────────────────────────────────────────────
# SCENARIO 4: Service account accessing datastores it shouldn't
# ETL service account regularly touches billing DB — not needed
# for its actual function
# ─────────────────────────────────────────────────────────────
@register_scenario
def scenario_service_account_overreach(users, events, sim_end, cfg=None):
    """
    The ETL service account has access to 4 datastores but only
    legitimately needs 2. Inject activity against the other 2
    to show it's actually using excess permissions.
    """
    svc_account = next((u for u in users if u.get("user_id") == "svc_etl_001"), None)
    if not svc_account:
        return events, []

    # Get from config: datastores svc_etl_001 has access to
    svc_role_ds = []
    for role in (cfg.get("iam_roles", []) if cfg else []):
        if role["id"] == "role-svc-etl":
            svc_role_ds = role.get("datastores", [])
    if svc_role_ds == ["*"]:
        svc_role_ds = [d["id"] for d in (cfg.get("datastores", []) if cfg else [])]
    # First half legitimate, second half excess (simplified heuristic)
    legitimate = svc_role_ds[:max(1, len(svc_role_ds)//2)]
    excess = svc_role_ds[max(1, len(svc_role_ds)//2):]
    if not excess:
        excess = legitimate[-1:]  # fallback

    injected = []
    sim_start = sim_end - timedelta(days=90)
    current = sim_start

    while current <= sim_end:
        if random.random() < 0.3:  # Every ~3 days
            ds_id = random.choice(excess)
            _ds_by_id = {d["id"]: d for d in (cfg.get("datastores", []) if cfg else [])}
            ds = _ds_by_id.get(ds_id)

            event_time = current.replace(
                hour=random.randint(1, 4),   # service accounts run at night
                minute=random.randint(0, 59)
            )

            event = {
                "event_id": f"evt_scen4_svc_{int(event_time.timestamp())}",
                "timestamp": event_time.isoformat(),
                "user_id": "svc_etl_001",
                "username": "svc-etl-pipeline",
                "action": "SELECT" if "rds" in ds_id else "GetObject",
                "datastore_id": ds_id,
                "datastore_name": ds["name"] if ds else ds_id,
                "datastore_classification": ds["classification"] if ds else "UNKNOWN",
                "bytes_transferred": random.randint(100_000, 10_000_000),
                "source_ip": "10.0.0.50",
                "region": "us-east-1",
                "status": "SUCCESS",
                "flags": ["EXCESS_PERMISSION_USED", "SERVICE_ACCOUNT_OVERREACH"],
                "scenario": "service_account_overreach"
            }
            injected.append(event)

        current += timedelta(days=1)

    finding = {
        "finding_id": "FIND-004",
        "scenario": "service_account_overreach",
        "severity": "HIGH",
        "title": "Service Account Actively Using Excess Permissions",
        "description": (
            "ETL pipeline service account (svc-etl-pipeline) has permissions to 4 datastores "
            f"but only requires 2 for its stated function. Over 90 days, it made {len(injected)} "
            "accesses to patient records (PHI) and billing database (PCI) — datastores with no "
            "documented ETL requirement."
        ),
        "affected_user": "svc_etl_001",
        "affected_datastore": excess,
        "event_count": len(injected),
        "detection_signals": [
            "Service account accessing PHI datastore with no documented requirement",
            "Service account accessing PCI datastore with no documented requirement",
            "Consistent pattern over 90 days — not one-time",
            "No change ticket or approval found for these access patterns",
            "Credentials not rotated in 340 days"
        ],
        "mitre_tactic": "TA0007 - Discovery",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "compliance_impact": ["HIPAA § 164.312(a)(1) - Access Control", "PCI DSS Req 7"],
        "recommended_action": "Scope service account to minimum required permissions, rotate credentials, audit all historical access"
    }

    return events + injected, [finding]


# ─────────────────────────────────────────────────────────────
# SCENARIO 5: Shadow data — PII found in dev/scratch bucket
# Someone copied a production dataset to the dev scratch bucket
# for testing. Never cleaned up. Now unprotected.
# ─────────────────────────────────────────────────────────────
@register_scenario
def scenario_shadow_data_in_dev(users, events, sim_end, cfg=None):
    """
    An engineer copied customer PII to the dev scratch bucket.
    The dev bucket has no encryption, no compliance controls.
    This is the 'shadow data' / data sprawl finding.
    """
    candidates = [u for u in users
                  if u.get("department") == "engineering"
                  and not u.get("account_type") == "service"]

    if not candidates:
        return events, []

    culprit = random.choice(candidates)
    copy_date = sim_end - timedelta(days=random.randint(45, 80))
    injected = []

    # The copy event
    copy_event = {
        "event_id": f"evt_scen5_{culprit['user_id']}_copy",
        "timestamp": copy_date.replace(hour=15, minute=23).isoformat(),
        "user_id": culprit["user_id"],
        "username": culprit.get("username"),
        "action": "CopyObject",
        "datastore_id": "s3-dev-scratch",
        "datastore_name": "meridian-dev-scratch-pad",
        "datastore_classification": "INTERNAL",  # bucket says INTERNAL but now contains PII
        "bytes_transferred": 450_000_000,  # 450MB of customer data
        "source_ip": generate_source_ip(culprit),
        "source_datastore": "s3-customer-pii",  # where it came from
        "region": "us-west-2",
        "status": "SUCCESS",
        "flags": ["DATA_SPRAWL", "PII_IN_UNCLASSIFIED_BUCKET", "SHADOW_DATA"],
        "scenario": "shadow_data_in_dev"
    }
    injected.append(copy_event)

    # Subsequent access by other engineers who found the data
    for _ in range(random.randint(5, 15)):
        accessor = random.choice(candidates)
        access_time = copy_date + timedelta(
            days=random.randint(1, (sim_end - copy_date).days),
            hours=random.randint(9, 18)
        )
        event = {
            "event_id": f"evt_scen5_{accessor['user_id']}_{int(access_time.timestamp())}",
            "timestamp": access_time.isoformat(),
            "user_id": accessor["user_id"],
            "username": accessor.get("username"),
            "action": "GetObject",
            "datastore_id": "s3-dev-scratch",
            "datastore_name": "meridian-dev-scratch-pad",
            "datastore_classification": "INTERNAL",
            "bytes_transferred": random.randint(1_000_000, 50_000_000),
            "source_ip": generate_source_ip(accessor),
            "region": "us-west-2",
            "status": "SUCCESS",
            "flags": ["ACCESSING_SHADOW_DATA"],
            "scenario": "shadow_data_in_dev"
        }
        injected.append(event)

    finding = {
        "finding_id": "FIND-005",
        "scenario": "shadow_data_in_dev",
        "severity": "HIGH",
        "title": "PII Data Found in Unclassified Development Bucket",
        "description": (
            f"{culprit['full_name']} copied 450MB from the customer PII datastore to the "
            f"dev scratch bucket on {copy_date.date()}. The dev bucket has no encryption enforcement, "
            f"no DLP controls, and broader access than production. "
            f"{len(injected)-1} subsequent accesses by other engineers detected."
        ),
        "affected_user": culprit["user_id"],
        "original_datastore": "s3-customer-pii",
        "shadow_datastore": "s3-dev-scratch",
        "copy_date": copy_date.isoformat(),
        "days_exposed": (sim_end - copy_date).days,
        "data_volume_bytes": 450_000_000,
        "secondary_accessors": len(injected) - 1,
        "detection_signals": [
            "Large CopyObject from PII-classified to INTERNAL-classified bucket",
            "Classification mismatch: PII data in non-PII bucket",
            "Dev bucket lacks encryption at rest enforcement",
            "Dev bucket accessible to all engineers (18 users)",
            f"Data exposed for {(sim_end - copy_date).days} days without remediation"
        ],
        "mitre_tactic": "TA0009 - Collection",
        "mitre_technique": "T1530 - Data from Cloud Storage",
        "compliance_impact": ["GDPR Art.25 - Data Protection by Design", "CCPA", "SOC2 CC6.1"],
        "recommended_action": "Delete copied data immediately, add bucket policy to prevent cross-classification copies, classify dev bucket correctly"
    }

    return events + injected, [finding]


def run_all_scenarios(users, events, sim_end, cfg=None):
    """
    Run all scenario injectors against the baseline.
    Returns enriched event list and all findings.
    """
    all_findings = []
    current_events = events

    for scenario_fn in SCENARIO_REGISTRY:
        print(f"  Running scenario: {scenario_fn.__name__}...")
        current_events, findings = scenario_fn(users, current_events, sim_end, cfg)
        all_findings.extend(findings)
        print(f"    → {len(findings)} finding(s) generated")

    return current_events, all_findings


if __name__ == "__main__":
    from users import generate_users, inject_departed_users, inject_service_accounts
    from activity import simulate_activity

    sim_end = datetime(2024, 3, 31)
    sim_start = datetime(2024, 1, 1)

    users = generate_users(sim_end)
    users = inject_departed_users(users, sim_end)
    service_accounts = inject_service_accounts(sim_end)
    all_identities = users + service_accounts

    print("Generating baseline activity...")
    events = simulate_activity(all_identities, sim_start, sim_end)

    print("\nInjecting scenarios...")
    events, findings = run_all_scenarios(all_identities, events, sim_end)

    print(f"\n{'='*50}")
    print(f"FINDINGS SUMMARY")
    print(f"{'='*50}")
    for f in findings:
        print(f"[{f['severity']:8}] {f['finding_id']} - {f['title']}")
