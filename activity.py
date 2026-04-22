"""
activity.py
Simulates activity over time. Reads datastores and roles from config.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import random
from datetime import datetime, timedelta

IP_RANGES = {
    "us-east-1": ["10.0.1.", "10.0.2.", "192.168.1."],
    "us-west-2": ["10.1.1.", "10.1.2.", "192.168.2."],
    "eu-west-1": ["10.2.1.", "10.2.2.", "192.168.3."],
}
FOREIGN_IPS = ["185.220.101.", "45.33.32.", "103.21.244.", "198.98.54."]

S3_ACTIONS  = [("GetObject",0.50),("PutObject",0.20),("ListBucket",0.15),("DeleteObject",0.05),("CopyObject",0.07),("GetBucketAcl",0.03)]
RDS_ACTIONS = [("SELECT",0.55),("INSERT",0.20),("UPDATE",0.15),("DELETE",0.05),("DESCRIBE",0.05)]
ACTION_VOLUMES = {
    "GetObject":(1024,5_000_000),"PutObject":(512,2_000_000),"ListBucket":(200,50_000),
    "DeleteObject":(0,0),"CopyObject":(1024,10_000_000),"SELECT":(500,500_000),
    "INSERT":(100,10_000),"UPDATE":(100,5_000),"DELETE":(0,0),"DESCRIBE":(200,2_000),
}

def weighted_choice(choices):
    return random.choices([c[0] for c in choices], weights=[c[1] for c in choices])[0]

def get_role_datastores(role_id, cfg):
    for role in cfg.get("iam_roles", []):
        if role["id"] == role_id:
            if role.get("datastores") == ["*"]:
                return [ds["id"] for ds in cfg.get("datastores", [])]
            return role.get("datastores", [])
    return []

def generate_source_ip(user, is_anomalous=False):
    if is_anomalous:
        return f"{random.choice(FOREIGN_IPS)}{random.randint(1,254)}"
    home = user.get("home_ip", "10.0.1.100")
    if random.random() < 0.05:
        parts = home.rsplit(".", 1)
        return f"{parts[0]}.{random.randint(10,250)}"
    return home

def generate_login_time(user, date):
    pattern = user.get("work_pattern_config", {})
    if not pattern:
        return None
    weekday = date.weekday()
    if weekday >= 5:
        wp = user.get("work_pattern", "standard")
        weekend_prob = {"oncall":0.3,"flexible":0.15,"extended":0.10,"standard":0.05,"early":0.03}.get(wp, 0.05)
        if random.random() > weekend_prob:
            return None
    base = pattern.get("core_start", 9) + (pattern.get("core_end", 18) - pattern.get("core_start", 9)) * 0.2
    hour = max(5, min(23, random.gauss(base, pattern.get("variance_hrs", 1.0))))
    return date.replace(hour=int(hour), minute=random.randint(0,59), second=random.randint(0,59))

def simulate_user_day(user, date, cfg):
    events = []
    login_time = generate_login_time(user, date)
    if not login_time:
        return events

    accessible = get_role_datastores(user.get("current_role","role-readonly"), cfg)
    # Add ghost role datastores
    for entry in user.get("role_history", []):
        if entry.get("flag") == "PERMISSION_DRIFT" and entry.get("revoked_date") is None:
            accessible = list(set(accessible + get_role_datastores(entry["role_id"], cfg)))

    if not accessible:
        return events

    dept = user.get("department", "")
    ds_by_id = {ds["id"]: ds for ds in cfg.get("datastores", [])}
    primary_ds = [ds_id for ds_id in accessible
                  if dept in ds_by_id.get(ds_id, {}).get("legitimate_accessors", [])]

    for _ in range(random.randint(1, 12)):
        if primary_ds and random.random() < 0.80:
            ds_id = random.choice(primary_ds)
        else:
            ds_id = random.choice(accessible)

        ds = ds_by_id.get(ds_id)
        if not ds:
            continue

        action = weighted_choice(S3_ACTIONS if ds["type"] == "s3_bucket" else RDS_ACTIONS)
        vol_range = ACTION_VOLUMES.get(action, (0, 1000))
        bytes_out = random.randint(vol_range[0], vol_range[1])
        event_time = login_time + timedelta(hours=random.uniform(0, 10))
        if event_time.hour > 23:
            event_time = event_time.replace(hour=22, minute=random.randint(0,59))

        events.append({
            "event_id": f"evt_{user['user_id']}_{int(event_time.timestamp())}_{random.randint(100,999)}",
            "timestamp": event_time.isoformat(),
            "user_id": user["user_id"],
            "username": user.get("username", "unknown"),
            "action": action,
            "datastore_id": ds_id,
            "datastore_name": ds["name"],
            "datastore_classification": ds["classification"],
            "bytes_transferred": bytes_out,
            "source_ip": generate_source_ip(user),
            "region": ds["region"],
            "status": "SUCCESS",
            "flags": []
        })
    return events

def simulate_activity(users, sim_start, sim_end, cfg):
    all_events = []
    total_days = (sim_end - sim_start).days
    print(f"  Simulating {total_days} days for {len(users)} identities...")
    current = sim_start
    day_count = 0
    while current <= sim_end:
        if day_count % 30 == 0:
            print(f"  Day {day_count}/{total_days}...")
        for user in users:
            all_events.extend(simulate_user_day(user, current, cfg))
        current += timedelta(days=1)
        day_count += 1
    return all_events
