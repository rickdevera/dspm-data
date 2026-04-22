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

**AI query layer — not built.** The output is structured to support it; adding it is a ~30-minute task on top of what exists. Set aside to keep focus on data quality, which is the harder problem.

**Web dashboard — not built.** The CLI query tool covers the same ground without adding dependencies. A visual interface is a reasonable next step, not a required one.

**Low-severity findings — not generated.** A real scan of an 80-person company would produce 50–150 findings, mostly low severity. This prototype surfaces 12 CRITICAL and HIGH findings. A post-simulation scan engine that auto-generates finding volume is architecturally straightforward — the data supports it, it just has not been built.

**Live cloud infrastructure — not used.** Output mirrors the AWS Security Hub schema so it could be ingested by real tooling. No AWS account is involved — the simulation generates what a real scan would find, not the infrastructure to scan.

**Two scenarios designed but not built:** behavioral drift (access pattern diverges from peers over 30 days) and temporary access abuse (elevated permissions not revoked, or post-revocation access to data discovered during the elevated window). Both require tracking how behavior changes over time — better suited to AI-assisted generation than fixed probability rules.

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — pipeline design, module responsibilities, config schema, extension points
- [CHANGELOG.md](CHANGELOG.md) — what changed between releases and migration notes
- [examples/](examples/) — sample output from a default run
- [WORKING_NOTES.md](WORKING_NOTES.md) — future architecture discussions (hybrid on-prem, AWS Outpost, data sovereignty)
