# DSPM Demo Environment

A simulation engine that generates a realistic, internally-consistent cloud security environment for a fictional company. It produces the kind of data a security tool would find after scanning a real environment — who has access to what, what they did with it, and where things went wrong.

Most security demos fail because the data is too clean. Every user has exactly the permissions they need. Behavior is perfectly uniform. Nothing drifts over time. Real environments do not work that way. This one does not either.

---

## What is DSPM?

**Data Security Posture Management (DSPM)** answers three questions about a company's cloud environment:

1. **Where is sensitive data?** — which S3 buckets, databases, and file stores contain PII, health records, payment data, or confidential files
2. **Who can access it?** — which users, service accounts, and automated systems have permissions to read, copy, or delete that data
3. **Is something wrong?** — misconfigurations, excessive access, unusual behavior, or data showing up where it should not be

This prototype generates a simulated cloud environment and produces findings across all three of those dimensions.

---

## Quick Start

**Requirements:** Python 3.9+ — no installs, no cloud account needed

```bash
git clone <repo>
cd dspm-demo

# Generate the default environment
python3 generate.py

# Explore what was generated
python3 query.py summary
python3 query.py findings
python3 query.py findings --severity CRITICAL
python3 query.py list-users
python3 query.py user <username>
python3 query.py datastore s3-patient-records

# Generate a different company
python3 generate.py --config configs/acme.json

# See all available configs
python3 generate.py --list-configs

# Fast test run (7 days instead of 90)
python3 generate.py --quick
```

---

## The Simulated Environment

### Default company — Meridian Health Analytics

A mid-market healthcare data company with 80 employees across 8 departments. Healthcare was chosen because it deals with multiple sensitive data types at once — patient records, payment data, employee information, and business data — which creates a richer set of security situations than a single-industry company.

### Alternate company — Acme Financial

A mid-market financial services company with a different risk profile — financial records, billing/PCI data, customer PII, and analytics datasets. Generated from `configs/acme.json` with no code changes.

### What gets generated

| File | What it contains |
|---|---|
| `output/company_baseline.json` | All users, their roles, and the data stores they can access |
| `output/activity_logs.json` | Every access event over 90 days — who touched what, when, from where, and how much data moved |
| `output/findings.json` | The security problems found — with evidence, severity, and recommended action |
| `output/summary.json` | A high-level snapshot of the environment |

---

## How the Simulation Works

### Identities have personality

Each of the 80 users is generated with a behavioral profile that stays consistent throughout the 90-day simulation:

- **Work schedule** — an engineer might log in anywhere between 7am and 10pm with high variance; a finance analyst is reliably 7am–4pm. Login times follow a probability distribution around each pattern rather than being assigned a fixed time.
- **Source IP** — every user has a consistent home IP range. When someone suddenly appears from a foreign IP address, it stands out because there is a baseline to compare against.
- **Role history** — users who have been at the company longer and changed roles have accumulated permissions over time. Old roles that were never removed when someone was promoted become a source of excess access. This happens naturally from the simulation logic, not by hardcoding a finding.
- **Normal data access** — each department has data stores it legitimately needs. Most activity (80%) stays within that expected range. The other 20% is within-permission but slightly outside normal — the kind of background noise that makes real log data hard to read.

### Scenarios are injected on top

Five security situations are layered into the baseline activity. Each scenario produces events that look unusual relative to the user's established normal behavior — not just random anomalies, but patterns that tell a story.

---

## Security Findings

### Current scenarios

| Severity | Finding | What the data shows |
|---|---|---|
| CRITICAL | Pre-departure data exfiltration | A user's download volume from a customer data store increases 40x over their final 14 days. Activity shifts to evening hours outside their normal work pattern. The escalation is sustained — not a one-time event. |
| CRITICAL | Credential compromise | A user's account accesses sensitive data stores from a foreign IP address between 1am and 5am over several days. Their normal access pattern is business hours from a known IP range. No travel was logged. |
| HIGH | Orphaned account | An employee left the company but their account was never disabled. The account continues accessing sensitive data stores weeks after their departure date. |
| HIGH | Service account with excess access | An automated pipeline account has permissions to four data stores but only needs two for its stated function. It is actively using the extra permissions — this is not just unused access, it is access being exercised. |
| HIGH | Sensitive data copied to wrong location | An engineer copies 450MB of customer records into a development data store that has no encryption requirements and is accessible to all 18 engineers. Fourteen of them subsequently access it. |

Each finding includes:
- What triggered it — the specific signals in the activity data
- MITRE ATT&CK technique mapping
- Which compliance frameworks are affected (HIPAA, GDPR, PCI-DSS, SOC2)
- Recommended action

### Planned scenarios

Two additional scenarios are designed but not yet built. Both require tracking how behavior changes over time — something that works better with AI-assisted generation than with fixed probability rules.

**Behavioral drift.** A user gradually starts accessing data outside their normal job function. There is no single suspicious event. The signal is that their access pattern diverges from their colleagues over 30 days. A help desk administrator who starts reading financial records with increasing frequency, while no one else in IT operations touches financial data at all, is an example.

**Temporary access abuse.** A user is granted elevated permissions for a specific task with an expiration date. Three things can go wrong: they access things outside the stated reason while the elevated access is active, the access is not removed when it expires, or — the most subtle signal — after the access is eventually removed, they attempt to reach data stores they only discovered because of the elevated window. That post-revocation attempt is evidence that what they saw during the elevated period shaped what they want to do next.

---

## Configuration

All environment parameters live in `config.json`. No code changes are needed to generate a different environment.

```bash
# See what configs exist
python3 generate.py --list-configs

# Run with a specific config
python3 generate.py --config configs/acme.json
```

Key settings:

```json
{
  "simulation": {
    "days": 90,
    "seed": 42
  },
  "departments": {
    "engineering": {
      "headcount": 18,
      "work_pattern": "flexible"
    }
  },
  "scenarios": {
    "enabled": ["pre_departure_exfil", "orphaned_account", "foreign_ip",
                "service_account_overreach", "shadow_data"]
  }
}
```

Setting `seed` to `null` generates a different environment on every run. Setting it to a number makes the output reproducible — useful for sharing a specific environment with someone else.

---

## Extending This

### Add a new scenario

```python
# In scenarios.py
@register_scenario
def scenario_your_name(users, events, sim_end, cfg=None):
    # pick target users
    # build and inject events
    # return updated events and a finding dict
    return events + injected, [finding]
```

The decorator handles registration automatically. It runs the next time `generate.py` is called.

### Add a new company

```bash
cp configs/acme.json configs/mycompany.json
# Edit the company name, departments, data stores, and IAM roles
python3 generate.py --config configs/mycompany.json
```

### Add an AI query layer

The output files are structured so an AI model can reason over them directly. Two options:

**Cloud-based (Claude API)** — better reasoning quality, requires an API key:

```python
import anthropic, json

client   = anthropic.Anthropic()
findings = json.load(open("output/findings.json"))

response = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    system="You are a security analyst reviewing cloud data access findings.",
    messages=[{
        "role": "user",
        "content": f"Review these findings and identify the highest priority risk: {findings}"
    }]
)
```

**Local (Ollama)** — fully offline, no API key needed, runs on your machine:

```bash
ollama run llama3
```

```python
import subprocess, json
findings = json.load(open("output/findings.json"))
subprocess.run(["ollama", "run", "llama3",
                f"Analyze these security findings: {findings}"])
```

One observation worth noting: running an AI model locally with no external connections is also a technique used by sophisticated attackers. The same local setup that lets a defender query security findings privately is what an attacker uses to reason about a target environment without leaving API logs. The architecture is identical — the intent is not.

---

## What Was Not Built and Why

**AI query layer.** The output is structured to support it. Adding it is a 30-minute task once the simulation data exists. It was set aside to keep focus on data quality, which is the harder problem.

**Web dashboard.** The command-line query tool covers the same ground without adding dependencies. A visual interface is a reasonable next step but not required to demonstrate the core idea.

**More findings.** A real scan of an 80-person company would produce 50 to 150 findings, mostly low severity, with a few important ones buried in the noise. This prototype generates 5 findings at the two highest severity levels. A post-simulation findings engine that scans users, data stores, and activity logs automatically would produce realistic volume and distribution. The architecture supports it — it just has not been built yet.

**Live cloud infrastructure.** The output format mirrors a real cloud security schema (AWS Security Hub) so the data could be ingested by a real tool. But no actual AWS account is involved. The simulation generates what a real scan would find — not the underlying infrastructure to scan.

---

## Project Structure

```
dspm-demo/
  generate.py         main entry point — runs the full simulation
  config_loader.py    reads and validates config files
  company.py          legacy static definitions (superseded by config.json)
  users.py            generates identities with behavioral profiles
  activity.py         simulates 90 days of access events
  scenarios.py        injects security scenarios into the baseline
  query.py            command-line tool for exploring output
  config.json         default environment (healthcare company)
  configs/
    acme.json         alternate environment (financial services company)
  output/
    company_baseline.json
    activity_logs.json
    findings.json
    summary.json
```
