# DSPM Generator 


The goal is for the  engine to generate flexible data that accurately represents and reflects real-world post-scan data, capturing the imperfections where permissions drift and behavior is inconsistent.


---

## Quick Start

**Requirements:** Python 3.9+ — no installs, no cloud account needed

```bash
git clone <repo>
cd dspm-demo

python3 generate.py                          # Generate the default environment
python3 query.py summary                     # Environment overview
python3 query.py findings                    # All findings
python3 query.py findings --severity CRITICAL
python3 query.py user <username>
python3 query.py datastore s3-patient-records

python3 generate.py --config configs/acme.json   # Alternate company (financial)
python3 generate.py --quick                       # 7-day test run
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

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — pipeline design, module responsibilities, config schema, extension points
- [CHANGELOG.md](CHANGELOG.md) — what changed between releases and migration notes
- [examples/](examples/) — sample output from a default run
- [WORKING_NOTES.md](WORKING_NOTES.md) — future architecture discussions (hybrid on-prem, AWS Outpost, data sovereignty)
