# Working Notes

---

## Deferred Features

Items that are architecturally supported but not yet built.

**Web dashboard** — The CLI query tool covers the same ground without adding dependencies. A visual interface is a reasonable next step but not required to demonstrate the core idea.

**Low-severity findings** — A real scan of an 80-person company would produce 50–150 findings, mostly low severity, with a few important ones buried in the noise. This prototype surfaces CRITICAL and HIGH findings only. A post-simulation scan engine that walks users, datastores, and activity logs automatically would produce realistic volume and distribution — the data structure supports it.

**Live cloud infrastructure** — Output mirrors the AWS Security Hub schema so it could be ingested by real tooling without code changes. No AWS account is involved — the simulation generates what a real scan would find, not the underlying infrastructure to scan.

**Behavioral drift scenario** — A user gradually starts accessing data outside their normal job function over 30 days. There is no single suspicious event — the signal is that their access pattern diverges from peers. Requires tracking relative behavior over time, which works better with AI-assisted generation than fixed probability rules.

**Temporary access abuse scenario** — A user is granted elevated permissions for a specific task. Three failure modes: accessing things outside the stated reason while elevated, permissions not removed on expiration, or post-revocation attempts to reach data discovered during the elevated window. The third signal is the most subtle and the most telling.

---

## FUTURE ARCHITECTURE DISCUSSIONS

---

### Topic 1: Hybrid Environment and On-Premises DSPM

**Current state**

The simulation only models cloud datastores (AWS S3, RDS). Real enterprise environments are hybrid — a mix of cloud and on-premises infrastructure that most DSPM tools handle unevenly.

**The core problem**

Cloud DSPM tools scan via cloud APIs with read-only IAM roles. On-premises has no equivalent abstraction layer — it requires network access, credentials, and agents or connectors deployed inside the network perimeter. Cloud-native DSPM tools generally do not support on-premises scanning without a connector or agent model.

**On-prem coverage — evaluation checklist**

| Capability | Validate |
|---|---|
| Native on-prem scanning (no agent required) | [ ] |
| Hybrid connector support (JDBC, agent-based) | [ ] |
| Active Directory identity resolution | [ ] |
| On-prem DLP heritage / file share scanning | [ ] |
| Coverage gap reporting for unscanned segments | [ ] |

**Two config templates needed (not one)**

Cloud datastore fields:
```json
{
  "infrastructure": "cloud",
  "cloud_provider": "aws",
  "region": "us-east-1",
  "resource_type": "s3_bucket",
  "encryption": "AES-256",
  "scan_method": "direct_api",
  "scan_coverage": "full"
}
```

On-prem datastore fields:
```json
{
  "infrastructure": "on_premises",
  "data_center": "Charlotte-DC1",
  "hostname": "ora-ehr-prod-01",
  "port": 1521,
  "version": "Oracle 19c",
  "access_control": "active_directory",
  "scan_method": "jdbc_connector",
  "scan_coverage": "partial",
  "coverage_gap": true,
  "coverage_gap_reason": "No DSPM agent deployed — requires network connector inside perimeter"
}
```

**Hybrid scenarios this unlocks**

1. **Data path traversal** — PHI moves from an on-prem Oracle EHR via ETL into AWS RDS. The cloud scanner finds PHI in the cloud but cannot see the on-prem origin or the movement path.

2. **Shadow replication** — A developer copies an on-prem SQL table to CSV and uploads it to an S3 dev bucket. The origin is invisible to the scanner; only the destination appears.

3. **Coverage gap exploitation** — An on-prem file share contains SSNs with no DSPM coverage. A user exfiltrates via VPN. Nothing is detected because the scanner has no visibility into that network segment.

4. **Hybrid identity confusion** — An Active Directory account (on-prem) is disabled after a departure, but the linked IAM role (cloud) remains active. Post-departure cloud access continues via IAM while the on-prem account is locked — the two identity planes are not reconciled.

**Config files to create later**

- `configs/hybrid_healthcare.json`
- `configs/onprem_legacy.json`

---

### Topic 2: AWS Outpost and Data Sovereignty

**What AWS Outpost is**

AWS-managed hardware physically installed in a customer's data center. Runs AWS services (S3, RDS, EKS) but data never leaves the building — cloud APIs and tooling with on-prem data residency. The distinction matters: it looks like AWS, but the physical boundary is inside a regulated facility.

**Why this breaks cloud DSPM assumptions**

Cloud DSPM scanners are region-based and require the scanner to be co-located with the data. For a standard AWS region this works as expected. For an AWS Outpost, the "region" is a customer's data center — and no external scanner has a deployment there. The assumption of reachability breaks entirely.

**Data sovereignty scenarios**

**Scenario A — Outpost with Direct Connect**
- Company has AWS Outpost in Charlotte data center with Direct Connect back to AWS us-east-1
- Risk: Scan metadata travels Charlotte → us-east-1
- May violate data residency requirements even though the underlying data stays local

**Scenario B — Sovereign cloud (EU)**
- EU healthcare company with data on AWS Outpost in Amsterdam
- GDPR requires data *and* metadata stay in EU
- Most DSPM platforms are US-based — sending classification metadata outside the EU creates a compliance violation
- DSPM coverage = zero for this environment

**Scenario C — Air-gapped Outpost**
- Government or defense contractor with Outpost disconnected from the public internet
- No external scanner can reach it
- Completely outside any cloud DSPM coverage by design

**Outpost / sovereignty coverage — evaluation checklist**

| Capability | Validate |
|---|---|
| Scanner can run inside Outpost boundary | [ ] |
| Metadata residency controls (stays in jurisdiction) | [ ] |
| Native cloud service integration (scope: S3 only?) | [ ] |
| On-prem connector for non-internet Outpost | [ ] |
| Hybrid governance model for split-jurisdiction environments | [ ] |

**Example config fields to add for Outpost datastores**

```json
{
  "infrastructure": "aws_outpost",
  "outpost_id": "op-0123456789abcdef",
  "physical_location": "Frankfurt, DE",
  "sovereignty_jurisdiction": "EU",
  "sovereignty_requirements": ["GDPR", "BDSG"],
  "data_residency_enforced": true,
  "scan_limitations": [
    "External scanner cannot reach Outpost without Direct Connect",
    "Metadata transit outside EU violates data residency policy"
  ],
  "coverage_gap": true,
  "coverage_gap_reason": "Sovereignty boundary prevents external DSPM scanning",
  "alternative_coverage": "native cloud service — S3 only, no RDS coverage"
}
```

**Example finding this unlocks**

```
FIND-013 | HIGH | DSPM Coverage Gap — Sovereignty Boundary

Datastore contains PHI subject to GDPR jurisdiction.
External DSPM scanning would require metadata to transit outside
the EU — violating data residency policy.

Current coverage: None
Recommended action: Evaluate native cloud services within Outpost boundary for object storage.
Evaluate connector-based DSPM for database workloads inside the sovereignty zone.
```

**Key insight**

Cloud-native DSPM tools assume the scanner can reach the data and send telemetry back to a central platform. AWS Outpost with sovereignty requirements breaks both assumptions. The data is on AWS infrastructure but physically inside a regulated boundary — even metadata about what is in the bucket may not leave that boundary. This is a growing gap as regulated industries adopt Outpost for exactly this reason.
