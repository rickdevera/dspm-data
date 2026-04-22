# Changelog

All notable changes to this project will be documented here.

## [Unreleased]

### Added

**Three new security scenarios (scenarios.py)**

| ID | Scenario | Severity | Signal |
|---|---|---|---|
| FIND-006 | `secrets_exposed` | CRITICAL | Credentials and secrets accessible to broad user population — hardcoded passwords, keys, and tokens in a config bucket with no encryption, accessed by 6+ engineers |
| FIND-007+ | `classification_mismatch` | HIGH | DSPM scanner found data types that exceed the bucket's stated classification label — e.g. a bucket labeled CONFIDENTIAL containing PHI/MRN data not reviewed in 669 days |
| FIND-010+ | `unencrypted_sensitive_data` | HIGH/CRITICAL | High or critical sensitivity datastores with `encryption: none` actively transferring data without protection |

Each new scenario follows the existing pattern: `@register_scenario` decorator, event injection into the activity log, and a structured finding dict with MITRE ATT&CK mapping, compliance impact, and recommended action.

**Rich datastore metadata (config.json)**

Each datastore now carries a full content profile aligned to the standard DSPM data taxonomy:

- `sensitivity_level` — four-tier hierarchy: `Public < Private < Confidential < Restricted` (replaces the old free-form `sensitivity` field)
- `category` — top-level data category (`PHI`, `PII`, `PCI`, `Financial`, `Internal`, `Secrets`)
- `encryption` — actual encryption state (`AES-256`, `AES-256 + TLS in-transit`, `none`)
- `public_access` — boolean
- `last_classified` / `classification_age_days` / `stale_classification` — classification freshness signals
- `secrets_risk` — boolean flag for credential exposure
- `file_formats_detected` — list of format objects with classification, type, extensions, and object/table count
- `data_types_detected` — granular list of detected data types with category, description, sensitivity level, and entry count
- `actual_data_types` / `labeled_data_types` — used by `classification_mismatch` to compute the gap
- `classification_mismatch` — boolean; triggers FIND-007+
- `sample_finding_evidence` — human-readable string showing what the scanner found (e.g. "SSN pattern XXX-XX-XXXX in 2.4M records")

Four datastores now explicitly flag classification mismatches:

| Datastore | Label | Actual highest data type | Age |
|---|---|---|---|
| `s3-analytics-raw` | CONFIDENTIAL | MRN, MBI (Restricted PHI) | 669 days |
| `s3-employee-records` | CONFIDENTIAL | SSN, Bank Account Number (Restricted PII) | 1,117 days |
| `s3-app-configs` | INTERNAL | Generic Password, Secret Key, Token (Restricted Secrets) | 816 days |
| `s3-data-lake` | CONFIDENTIAL | MRN, MBI, SSN (Restricted PHI/PII), Credit Card Number (Restricted PCI) | 1,217 days |

`s3-data-lake` (`meridian-data-lake-raw`) is the largest affected store: 45M records across 84,200 parquet/csv objects, last classified 2020-11-30. The scanner found SSN in insurance claim feeds (8.2M entries), Credit Card Numbers in payment feeds (340K entries), and MRN across the full object corpus.

Two datastores flag secrets risk with no encryption (`s3-dev-scratch`, `s3-app-configs`).

### Changed

**generate.py — datastore summary updated to new field names**

```python
# Before
"critical_sensitivity": sum(1 for d in datastores if d["sensitivity"] == "critical"),
"phi_datastores":       sum(1 for d in datastores if d["classification"] == "PHI"),

# After
"critical_sensitivity": sum(1 for d in datastores if d.get("sensitivity_level") == "Restricted"),
"phi_datastores":       sum(1 for d in datastores if d.get("category") == "PHI"),
```

**config_loader.py — scenario validation updated**

`secrets_exposed`, `classification_mismatch`, and `unencrypted_sensitive_data` added to the known scenarios set so they can be listed in `config.json` without triggering a validation error.

### Migration notes

If you have any code querying `d["sensitivity"]` directly (e.g. custom filters in `query.py` or external scripts), switch to `d.get("sensitivity_level")`. The old values (`critical`, `high`, `medium`) map to the new hierarchy as:

| Old | New |
|---|---|
| `critical` | `Restricted` |
| `high` | `Restricted` or `Confidential` (depends on data type) |
| `medium` | `Confidential` or `Private` |
| `low` | `Private` or `Public` |

---

## [0.1.0] — Initial release

- Config-driven simulation engine for a fictional 80-person healthcare company (Meridian Health Analytics)
- Five baseline security scenarios: pre-departure exfiltration, orphaned account, foreign IP credential compromise, service account overreach, shadow data copy
- Alternate company config (`configs/acme.json`) — financial services profile
- CLI query tool (`query.py`) for exploring generated output
- Output format mirrors AWS Security Hub schema
