# Architecture

## Design Philosophy

The simulation is built around one principle: realism comes from consistent identity, not random noise. Every output — an access event, a security finding, a flagged anomaly — is traceable back to a user's behavioral profile and role history. Nothing is hardcoded as "suspicious." Suspicious things emerge from the contrast between a user's established baseline and what they actually did.

---

## Pipeline Overview

```
config.json
    │
    ▼
config_loader.py         Load + validate + seed RNG
    │
    ▼
users.py                 Generate identities with behavioral profiles
    │
    ▼
activity.py              Simulate N days of access events per identity
    │
    ▼
scenarios.py             Inject security scenarios on top of baseline
    │
    ▼
generate.py              Orchestrate, assemble, write output files
    │
    ├── output/company_baseline.json
    ├── output/activity_logs.json
    ├── output/findings.json
    └── output/summary.json
```

`query.py` reads the output files independently — it has no dependency on the simulation modules.

---

## Module Responsibilities

### `config_loader.py`
Single source of truth for the environment definition. Loads `config.json` (or an alternate path), seeds the RNG, and exposes typed accessors (`get_company`, `get_departments`, `get_datastores`, etc.) so simulation modules never read the config dict directly.

The module-level cache ensures all simulation modules share one config instance per run — important because the RNG seed is applied at load time.

### `users.py`
Generates three identity types from config:

**Employees** (`generate_users`) — built from department headcount. Each user gets:
- A behavioral profile: work pattern, home IP range, login-time variance
- A role assignment: driven by seniority tier within the department
- A role history: senior engineers with long tenure accumulate permission drift naturally — the ghost role is added to `role_history` with `"revoked_date": null` and `"flag": "PERMISSION_DRIFT"`

**Departed employees** (`inject_departed_users`) — users with a `departure_date` in the past, `is_active: true`, `is_departed: true`. The combination is the finding: active flag was never cleared.

**Service accounts** (`inject_service_accounts`) — loaded directly from config. Each has a stated function, a role, and a credentials age that may trigger a finding.

### `activity.py`
The core simulation loop. For each day in the simulation window, for each identity:

1. `generate_login_time` — draws from a Gaussian distribution around the user's `core_start` hour. Weekends are skipped at a rate proportional to work pattern type.
2. `get_role_datastores` — resolves the user's current role (and any live ghost roles) to a list of accessible datastore IDs.
3. Access events — 1–12 events per active day. 80% of events target `primary_ds` (datastores where the user's department appears in `legitimate_accessors`); 20% go to any accessible store. This 80/20 split is the realistic noise floor that makes anomalies detectable.

Event fields mirror the AWS CloudTrail schema: `event_id`, `timestamp`, `user_id`, `action`, `datastore_id`, `bytes_transferred`, `source_ip`, `region`, `status`, `flags`.

### `scenarios.py`
Injects security scenarios as additional events on top of the baseline. Each scenario:
- Is a plain function decorated with `@register_scenario`
- Receives the full identity list, the accumulated event list, `sim_end`, and the config
- Returns `(updated_events, findings_list)`

`run_all_scenarios` calls each registered function in order, threading state through. Scenarios that find no suitable target (e.g., no eligible departed user) return the inputs unchanged rather than failing.

Current scenarios and their injection mechanism:

| Scenario | What it injects |
|---|---|
| `pre_departure_exfil` | 3–8 large download events per day in the final 14 days, after-hours, from a sales/CS user |
| `orphaned_account` | Post-departure access events from a departed user whose account was never disabled |
| `foreign_ip` | Nighttime (1–5am) access events from a foreign IP range against a sensitive datastore |
| `service_account_overreach` | Access events from a service account to datastores outside its stated function |
| `shadow_data` | A bulk copy event followed by subsequent reads of that data by other engineers |
| `secrets_exposed` | Read events from an unencrypted config bucket containing credentials |
| `classification_mismatch` | A finding (no new events) derived from `classification_mismatch: true` on datastore metadata |
| `unencrypted_sensitive_data` | Findings derived from `encryption: none` on high/critical datastores, correlated with observed transfer volume |

### `generate.py`
The orchestrator. Calls each module in pipeline order, assembles output dicts, and writes four JSON files. Findings are decorated with AWS Security Hub envelope fields (`ProductArn`, `AwsAccountId`, `Workflow`, `RecordState`) before writing — this makes the output ingestible by real tooling without code changes.

### `query.py`
A standalone CLI that reads the output files and renders them for human inspection. No dependency on simulation code — it can be run on any output directory. Commands: `summary`, `findings`, `user <username>`, `datastore <id>`, `list-users`, `timeline <user_id>`.

---

## Config Schema

The config file controls the entire environment. No code changes are needed to generate a different company.

```
config.json
├── company              Name, industry, primary_region
├── simulation           days, end_date, seed (null = random)
├── departments          headcount, work_pattern, base_region per dept
├── work_patterns        core_start, core_end, variance_hrs per pattern type
├── identity_settings    mfa_adoption_rate, ghost_role_probability, tenure thresholds
├── datastores[]         id, name, type, sensitivity_level, category, encryption,
│                        classification, legitimate_accessors, data_types_detected,
│                        classification_mismatch, secrets_risk, sample_finding_evidence
├── iam_roles[]          id, datastores[] (can be "*" for wildcard)
├── service_accounts[]   user_id, username, role, credentials_age_days, flag
└── scenarios            enabled: [list of scenario names]
```

The `datastores[].legitimate_accessors` field drives the 80/20 baseline split in `activity.py` — it is the mechanism that makes some access normal and some access anomalous, without any per-user hardcoding.

---

## Randomness and Reproducibility

All randomness flows through Python's `random` module. The seed is applied once in `config_loader.load_config()` before any simulation code runs. `scenarios.py` applies a second fixed seed (`random.seed(99)`) at module load to maintain scenario variety independent of the baseline seed.

Setting `"seed": null` in config generates a different environment on every run. Setting it to any integer makes the output byte-for-byte reproducible — useful for sharing a specific environment.

---

## Output Schema

All output files are JSON. `activity_logs.json` and `findings.json` carry a `schema_version` field for forward compatibility.

**`company_baseline.json`** — identities, datastores, IAM roles, simulation metadata

**`activity_logs.json`** — flat array of events, CloudTrail-compatible field names, `schema_note` flagging AWS Security Hub compatibility

**`findings.json`** — array of findings, each with: `finding_id`, `severity`, `title`, `description`, `affected_user`, `mitre_technique`, `compliance`, `recommendation`, `signals`, `evidence_events`, plus AWS Security Hub envelope fields

**`summary.json`** — aggregated counts across identities, datastores, activity, and findings. The format `query.py summary` renders.

---

## Extension Points

**Add a scenario** — decorate a function with `@register_scenario` in `scenarios.py`. It receives `(users, events, sim_end, cfg)` and returns `(events, findings)`. Register the name in `config_loader.validate_config` so it can appear in `config.json` without triggering a validation error.

**Add a company** — copy an existing config file under `configs/`, change company metadata, departments, datastores, and IAM roles. Run with `--config configs/yourfile.json`. No code changes.

**Add a datastore field** — add it to `config.json`. The simulation passes the full datastore dict to scenarios, so new fields are immediately available to scenario logic and appear in output.

**Add a query command** — add a `cmd_<name>` function in `query.py` and register it in the `argparse` subparser block at the bottom of the file.
