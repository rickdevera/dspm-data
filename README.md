# DSPM Generator 


The goal is for the  engine to generate flexible data that accurately represents and reflects real-world post-scan data, capturing the imperfections where permissions drift and behavior is inconsistent.


---

## Quick Start

**Requirements:** Python 3.9+ — no installs, no cloud account needed

```bash
git clone <repo>
cd dspm-demo

# Step 1 — generate the environment (writes to output/)
python3 generate.py                              # default: Meridian Health (config.json)
python3 generate.py --config configs/acme.json   # alternate: Acme Financial
python3 generate.py --quick                       # 7-day test run

# Step 2 — explore what was generated
# query.py always reads from output/ — it reflects whatever generate.py last produced
python3 query.py summary
python3 query.py findings
python3 query.py findings --severity CRITICAL
python3 query.py user <username>
python3 query.py datastore s3-patient-records

# timeline — pipe-friendly, outputs all events with username on every line
python3 query.py timeline                        # all events
python3 query.py timeline <username>             # filter to one user
python3 query.py timeline | grep EXFIL_PATTERN
python3 query.py timeline | grep s3-customer-pii
python3 query.py timeline | grep FOREIGN_IP
```

---

## Output

| File | Contents |
|---|---|
| `output/company_baseline.json` | Users, roles, and datastore access |
| `output/activity_logs.json` | Every access event over 90 days — who, what, when, from where, how much data |
| `output/findings.json` | Security findings with evidence, MITRE mapping, compliance impact, and recommended action |
| `output/summary.json` | High-level environment snapshot |

See [`examples/`](examples/) for sample output from a default run.

---

## Decisions and Tradeoffs

**Config-driven design** — The environment is fully defined in `config.json` with no code changes needed to generate a different company. This makes the simulation reproducible via a seed value and extensible to new industries without touching the pipeline. A hardcoded approach would have produced one demo environment; the config approach produces an unlimited number of internally consistent ones.

**Healthcare as the domain** — Healthcare surfaces multiple sensitive data types simultaneously: PHI (MRN, MBI, DEA), PII (SSN, name, address), PCI (payment data), and credentials. A single-type dataset produces narrow findings. Healthcare creates overlapping compliance scope — HIPAA, GDPR, PCI-DSS, SOC2 — in one environment, which is a more realistic and interesting demo target.

**MITRE ATT&CK mapping** — Every finding maps to a tactic and technique. This is the shared language between DSPM output and the security operations teams that act on findings — it determines which detection playbooks apply and where in the kill chain the activity sits. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full mapping rationale.

**AI query layer** — The output format (structured JSON, AWS Security Hub schema) was chosen specifically to support it. Set aside to keep focus on data quality, which is the harder problem. See [WORKING_NOTES.md](WORKING_NOTES.md) for the planned approach.

**On-prem and hybrid coverage** — Out of scope for this prototype due to time constraints. Extending to on-prem requires a fundamentally different scanning model — connectors, agents, no cloud API abstraction. See [WORKING_NOTES.md](WORKING_NOTES.md) for the architecture discussion.

---

## Known Limitations

- `--severity` does not validate input — a misspelling returns zero results with no error message
- `query.py list-users` shows a maximum of 6 users per department; larger departments are silently truncated
- `query.py timeline` outputs all events — large environments will produce significant output; pipe to `grep` or `head` to narrow results
- `query.py summary` labels the activity period as "90 days" regardless of whether `--quick` was used
- Datastore ID lookup is case-sensitive; username lookup is not — behavior is inconsistent across commands

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — pipeline design, module responsibilities, config schema, extension points
- [CHANGELOG.md](CHANGELOG.md) — what changed between releases and migration notes
- [examples/](examples/) — sample output from a default run
- [WORKING_NOTES.md](WORKING_NOTES.md) — future architecture discussions (hybrid on-prem, AWS Outpost, data sovereignty)
