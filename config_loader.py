"""
config_loader.py
Reads the config file and exposes it to all simulation modules.
Replaces hardcoded values in company.py, users.py, activity.py, scenarios.py.

Usage:
    from config_loader import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import load_config
    cfg = load_config()                        # loads config.json (default)
    cfg = load_config("configs/fintech.json")  # loads alternate config
"""

import json
import os
import random

_config_cache = None
_config_path = None


def load_config(path=None):
    """
    Load and return the simulation config.
    Caches after first load so all modules share the same instance.
    """
    global _config_cache, _config_path

    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

    # Always resolve to absolute path so cache comparison works
    # regardless of whether a relative or absolute path was passed
    path = os.path.abspath(path)

    # Return cached config if already loaded from same path
    if _config_cache is not None and _config_path == path:
        return _config_cache

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Expected config.json in project root, or pass a path explicitly."
        )

    with open(path) as f:
        cfg = json.load(f)

    # Apply seed — null means random every run
    seed = cfg.get("simulation", {}).get("seed")
    if seed is not None:
        random.seed(seed)
        print(f"  [config] Seed: {seed} (reproducible output)")
    else:
        import time
        seed = int(time.time())
        random.seed(seed)
        print(f"  [config] Seed: {seed} (random — save this to reproduce)")

    _config_cache = cfg
    _config_path = path

    return cfg


def get_company(cfg):
    return cfg.get("company", {})


def get_departments(cfg):
    return cfg.get("departments", {})


def get_datastores(cfg):
    return cfg.get("datastores", [])


def get_iam_roles(cfg):
    return cfg.get("iam_roles", [])


def get_work_patterns(cfg):
    return cfg.get("work_patterns", {})


def get_scenarios_config(cfg):
    return cfg.get("scenarios", {})


def get_service_accounts_config(cfg):
    return cfg.get("service_accounts", [])


def get_identity_settings(cfg):
    return cfg.get("identity_settings", {
        "mfa_adoption_rate": 0.85,
        "ghost_role_probability": 0.4,
        "min_tenure_for_drift_days": 540,
        "password_max_age_days": 365
    })


def get_simulation_settings(cfg):
    return cfg.get("simulation", {
        "days": 90,
        "end_date": "2024-03-31",
        "seed": 42
    })


def validate_config(cfg):
    """
    Basic validation — catch common config errors before simulation runs.
    Returns list of errors (empty = valid).
    """
    errors = []

    # Required top-level keys
    for key in ["company", "departments", "datastores", "iam_roles", "scenarios"]:
        if key not in cfg:
            errors.append(f"Missing required key: '{key}'")

    # Departments need work_pattern that exists in work_patterns
    patterns = cfg.get("work_patterns", {})
    for dept_name, dept in cfg.get("departments", {}).items():
        wp = dept.get("work_pattern")
        if wp and wp not in patterns:
            errors.append(f"Department '{dept_name}' references unknown work_pattern: '{wp}'")
        if dept.get("headcount", 0) < 1:
            errors.append(f"Department '{dept_name}' headcount must be >= 1")

    # Datastores need unique IDs
    ds_ids = [d.get("id") for d in cfg.get("datastores", [])]
    if len(ds_ids) != len(set(ds_ids)):
        errors.append("Duplicate datastore IDs found")

    # IAM roles need unique IDs
    role_ids = [r.get("id") for r in cfg.get("iam_roles", [])]
    if len(role_ids) != len(set(role_ids)):
        errors.append("Duplicate IAM role IDs found")

    # Scenarios reference valid datastore IDs
    valid_ds_ids = set(ds_ids)
    for role in cfg.get("iam_roles", []):
        for ds_id in role.get("datastores", []):
            if ds_id != "*" and ds_id not in valid_ds_ids:
                errors.append(f"IAM role '{role.get('id')}' references unknown datastore: '{ds_id}'")

    # Enabled scenarios must be known
    known_scenarios = {
        "pre_departure_exfil", "orphaned_account", "foreign_ip",
        "service_account_overreach", "shadow_data",
        "secrets_exposed", "classification_mismatch", "unencrypted_sensitive_data"
    }
    enabled = cfg.get("scenarios", {}).get("enabled", [])
    for s in enabled:
        if s not in known_scenarios:
            errors.append(f"Unknown scenario: '{s}'. Known: {sorted(known_scenarios)}")

    return errors


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else None
    cfg = load_config(path)

    errors = validate_config(cfg)
    if errors:
        print(f"\n[!] Config validation errors:")
        for e in errors:
            print(f"    - {e}")
    else:
        print(f"\n[✓] Config valid")
        print(f"    Company:     {cfg['company']['name']}")
        print(f"    Industry:    {cfg['company']['industry']}")
        print(f"    Departments: {len(cfg['departments'])}")
        dept_total = sum(d.get('headcount', 0) for d in cfg['departments'].values())
        print(f"    Headcount:   {dept_total}")
        print(f"    Datastores:  {len(cfg['datastores'])}")
        print(f"    IAM roles:   {len(cfg['iam_roles'])}")
        print(f"    Scenarios:   {cfg['scenarios'].get('enabled', [])}")
