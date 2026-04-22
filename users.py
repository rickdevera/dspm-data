"""
users.py
Generates the fictional company's workforce from config.
Users have behavioral DNA that drives consistent activity patterns.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import random
import json
from datetime import datetime, timedelta

FIRST_NAMES = [
    "James", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert", "Ashley",
    "John", "Jennifer", "William", "Amanda", "Christopher", "Melissa", "Daniel",
    "Stephanie", "Matthew", "Nicole", "Anthony", "Elizabeth", "Mark", "Heather",
    "Donald", "Amber", "Steven", "Rachel", "Paul", "Megan", "Andrew", "Lauren",
    "Kenneth", "Brittany", "Joshua", "Danielle", "Kevin", "Chelsea", "Brian",
    "Samantha", "George", "Crystal", "Timothy", "Maria", "Ronald", "Michelle",
    "Edward", "Lisa", "Jason", "Anna", "Jeffrey", "Sandra", "Ryan", "Patricia"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen",
    "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera",
    "Campbell", "Mitchell", "Carter", "Roberts"
]

IP_RANGES = {
    "us-east-1": ["10.0.1.", "10.0.2.", "192.168.1."],
    "us-west-2": ["10.1.1.", "10.1.2.", "192.168.2."],
    "eu-west-1": ["10.2.1.", "10.2.2.", "192.168.3."],
}


def _get_role_map(cfg):
    """Build dept->role mapping from config IAM roles."""
    roles = {r["id"]: r for r in cfg.get("iam_roles", [])}
    depts = list(cfg.get("departments", {}).keys())
    # Best-effort mapping: match role names to departments
    role_map = {}
    for dept in depts:
        # Find roles by keyword match
        senior = next((r for r in roles if dept[:4] in r or "senior" in r), "role-readonly")
        standard = next((r for r in roles if dept[:4] in r), "role-readonly")
        role_map[dept] = {"senior": senior, "standard": standard}
    # Explicit overrides for common department names
    overrides = {
        "engineering": {"senior": "role-engineer-senior", "standard": "role-engineer-dev"},
        "data_science": {"senior": "role-data-scientist", "standard": "role-data-scientist"},
        "finance":      {"senior": "role-finance",         "standard": "role-finance"},
        "hr":           {"senior": "role-hr",              "standard": "role-hr"},
        "sales":        {"senior": "role-sales",           "standard": "role-sales"},
        "customer_success": {"senior": "role-sales",       "standard": "role-sales"},
        "legal":        {"senior": "role-readonly",        "standard": "role-readonly"},
        "it_ops":       {"senior": "role-admin",           "standard": "role-engineer-senior"},
        "fraud_risk":   {"senior": "role-fraud-analyst",   "standard": "role-fraud-analyst"},
        "compliance":   {"senior": "role-compliance",      "standard": "role-compliance"},
        "operations":   {"senior": "role-sales",           "standard": "role-sales"},
    }
    role_map.update({k: v for k, v in overrides.items() if k in depts})
    return role_map


def assign_role(dept_name, is_senior, is_manager, role_map):
    mapping = role_map.get(dept_name, {"senior": "role-readonly", "standard": "role-readonly"})
    if is_manager and dept_name == "it_ops":
        return "role-admin"
    return mapping["senior"] if is_senior else mapping["standard"]


def generate_hire_date(sim_end_date, min_days_ago=30, max_days_ago=1825):
    weights = [3 if 365 < d < 1095 else 1 for d in range(min_days_ago, max_days_ago)]
    days_ago = random.choices(range(min_days_ago, max_days_ago), weights=weights)[0]
    return sim_end_date - timedelta(days=days_ago)


def generate_home_ip(region):
    base = random.choice(IP_RANGES.get(region, IP_RANGES["us-east-1"]))
    return f"{base}{random.randint(10, 250)}"


def generate_users(sim_end_date, cfg):
    from config_loader import get_departments, get_identity_settings
    departments = get_departments(cfg)
    id_settings = get_identity_settings(cfg)
    work_patterns = cfg.get("work_patterns", {})
    role_map = _get_role_map(cfg)

    mfa_rate = id_settings.get("mfa_adoption_rate", 0.85)
    ghost_prob = id_settings.get("ghost_role_probability", 0.4)
    min_drift_days = id_settings.get("min_tenure_for_drift_days", 540)

    users = []
    user_id = 1000

    for dept_name, dept_config in departments.items():
        headcount = dept_config.get("headcount", 5)
        pattern = dept_config.get("work_pattern", "standard")
        region = dept_config.get("base_region", "us-east-1")

        for i in range(headcount):
            is_manager = (i == 0)
            is_senior  = (i < headcount // 3)

            first = random.choice(FIRST_NAMES)
            last  = random.choice(LAST_NAMES)
            username = f"{first.lower()}.{last.lower()}{random.randint(1,9) if random.random() > 0.7 else ''}"

            hire_date    = generate_hire_date(sim_end_date)
            tenure_days  = (sim_end_date - hire_date).days
            current_role = assign_role(dept_name, is_senior, is_manager, role_map)

            role_history = []
            # Tenure-based role accumulation — drift source
            if tenure_days > 730 and is_senior and dept_name == "engineering":
                role_history.append({
                    "role_id": "role-engineer-dev",
                    "granted_date": hire_date.isoformat(),
                    "revoked_date": (hire_date + timedelta(days=540)).isoformat(),
                    "reason": "initial_role"
                })

            has_ghost_role = (
                dept_name == "engineering" and is_senior
                and tenure_days > min_drift_days
                and random.random() < ghost_prob
            )
            if has_ghost_role:
                role_history.append({
                    "role_id": "role-engineer-dev",
                    "granted_date": (hire_date + timedelta(days=180)).isoformat(),
                    "revoked_date": None,
                    "reason": "never_revoked_on_promotion",
                    "flag": "PERMISSION_DRIFT"
                })

            role_history.append({
                "role_id": current_role,
                "granted_date": (hire_date + timedelta(days=max(0, tenure_days - 365))).isoformat(),
                "revoked_date": None,
                "reason": "current"
            })

            users.append({
                "user_id": f"usr_{user_id}",
                "employee_id": f"EMP{random.randint(10000,99999)}",
                "username": username,
                "email": f"{username}@{cfg['company'].get('name','company').lower().replace(' ','')}.io",
                "full_name": f"{first} {last}",
                "department": dept_name,
                "title": _generate_title(dept_name, is_manager, is_senior),
                "manager": None,
                "hire_date": hire_date.isoformat(),
                "tenure_days": tenure_days,
                "is_active": True,
                "is_manager": is_manager,
                "is_senior": is_senior,
                "region": region,
                "home_ip": generate_home_ip(region),
                "work_pattern": pattern,
                "work_pattern_config": work_patterns.get(pattern, work_patterns.get("standard", {})),
                "current_role": current_role,
                "role_history": role_history,
                "has_ghost_role": has_ghost_role,
                "risk_score": 0.0,
                "mfa_enabled": random.random() < mfa_rate,
                "last_password_change": (sim_end_date - timedelta(days=random.randint(1,365))).isoformat(),
            })
            user_id += 1

    # Assign managers
    dept_managers = {u["department"]: u["user_id"] for u in users if u["is_manager"]}
    for u in users:
        if not u["is_manager"]:
            u["manager"] = dept_managers.get(u["department"])

    return users


def inject_departed_users(users, sim_end_date, cfg):
    from config_loader import get_departments, get_scenarios_config
    departments = get_departments(cfg)
    scen_cfg = get_scenarios_config(cfg)
    orphan_cfg = scen_cfg.get("orphaned_accounts", {})
    work_patterns = cfg.get("work_patterns", {})

    count    = orphan_cfg.get("count", 4)
    min_days = orphan_cfg.get("min_days_since_departure", 30)
    max_days = orphan_cfg.get("max_days_since_departure", 120)
    departed = []

    for i in range(count):
        dept_name   = random.choice(list(departments.keys()))
        dept_config = departments[dept_name]
        first = random.choice(FIRST_NAMES)
        last  = random.choice(LAST_NAMES)
        username       = f"{first.lower()}.{last.lower()}_old"
        departure_date = sim_end_date - timedelta(days=random.randint(min_days, max_days))
        hire_date      = departure_date - timedelta(days=random.randint(365, 1460))
        pattern        = dept_config.get("work_pattern", "standard")

        departed.append({
            "user_id": f"usr_dep_{i+1}",
            "employee_id": f"EMP{random.randint(10000,99999)}",
            "username": username,
            "email": f"{username}@{cfg['company'].get('name','company').lower().replace(' ','')}.io",
            "full_name": f"{first} {last}",
            "department": dept_name,
            "title": _generate_title(dept_name, False, False),
            "hire_date": hire_date.isoformat(),
            "departure_date": departure_date.isoformat(),
            "tenure_days": (departure_date - hire_date).days,
            "is_active": True,
            "is_departed": True,
            "region": dept_config.get("base_region", "us-east-1"),
            "home_ip": generate_home_ip(dept_config.get("base_region", "us-east-1")),
            "work_pattern": pattern,
            "work_pattern_config": work_patterns.get(pattern, {}),
            "current_role": "role-readonly",
            "role_history": [],
            "has_ghost_role": False,
            "mfa_enabled": False,
            "flag": "ORPHANED_ACCOUNT",
            "risk_score": 0.8,
        })

    return users + departed


def inject_service_accounts(sim_end_date, cfg):
    from config_loader import get_service_accounts_config
    svc_configs = get_service_accounts_config(cfg)
    work_patterns = cfg.get("work_patterns", {})
    service_accounts = []

    for sc in svc_configs:
        created_days_ago = sc.get("credentials_age_days", 365) + random.randint(0, 200)
        service_accounts.append({
            "user_id": sc["user_id"],
            "username": sc["username"],
            "email": f"{sc['username']}@{cfg['company'].get('name','company').lower().replace(' ','')}.io",
            "full_name": sc.get("description", sc["username"]),
            "account_type": "service",
            "department": sc.get("department", "engineering"),
            "current_role": sc.get("role", "role-readonly"),
            "created_date": (sim_end_date - timedelta(days=created_days_ago)).isoformat(),
            "last_rotated": (sim_end_date - timedelta(days=sc.get("credentials_age_days", 365))).isoformat(),
            "is_active": True,
            "region": cfg["company"].get("primary_region", "us-east-1"),
            "home_ip": sc.get("home_ip", "10.0.0.50"),
            "work_pattern": "oncall",
            "work_pattern_config": work_patterns.get("oncall", {}),
            "mfa_enabled": False,
            "flag": sc.get("flag", ""),
            "notes": sc.get("description", ""),
            "risk_score": 0.9,
            "role_history": [],
            "has_ghost_role": False,
        })

    return service_accounts


def _generate_title(dept_name, is_manager, is_senior):
    titles = {
        "engineering":       ("Engineering Manager",   "Senior Software Engineer",      "Software Engineer"),
        "data_science":      ("Head of Data Science",  "Senior Data Scientist",          "Data Scientist"),
        "finance":           ("Finance Director",       "Senior Financial Analyst",       "Financial Analyst"),
        "hr":                ("HR Director",            "Senior HR Business Partner",     "HR Specialist"),
        "sales":             ("VP of Sales",            "Senior Account Executive",       "Account Executive"),
        "customer_success":  ("Head of Customer Success","Senior Customer Success Manager","Customer Success Manager"),
        "legal":             ("General Counsel",        "Senior Legal Counsel",           "Legal Associate"),
        "it_ops":            ("IT Operations Manager",  "Senior Systems Engineer",        "Systems Administrator"),
        "fraud_risk":        ("Head of Fraud Risk",     "Senior Fraud Analyst",           "Fraud Analyst"),
        "compliance":        ("Chief Compliance Officer","Senior Compliance Analyst",     "Compliance Analyst"),
        "operations":        ("VP Operations",          "Senior Operations Manager",      "Operations Analyst"),
    }
    t = titles.get(dept_name, ("Manager", "Senior Analyst", "Analyst"))
    return t[0] if is_manager else (t[1] if is_senior else t[2])
