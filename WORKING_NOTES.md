# Working Notes

---

## FUTURE ARCHITECTURE DISCUSSIONS

---

### Topic 1: Hybrid Environment and On-Premises DSPM

**Current state**

The simulation only models cloud datastores (AWS S3, RDS). Real enterprise environments are hybrid — a mix of cloud and on-premises infrastructure that most DSPM tools handle unevenly.

**The core problem**

Cloud DSPM tools scan via cloud APIs with read-only IAM roles. On-premises has no equivalent abstraction layer — it requires network access, credentials, and agents or connectors deployed inside the network perimeter. Tenable Cloud Security does not support on-premises scanning.

**Who covers on-prem**

| Vendor | On-Prem Coverage |
|---|---|
| Varonis | Strongest on-prem story |
| BigID | Hybrid connectors |
| Netwrix | On-prem focused |
| Fortra / Digital Guardian | On-prem DLP heritage |

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

Tenable's scanner is region-based and requires the scanner to be co-located with the data. The Tenable FAQ states: *"Scanning is outpost-based and region-specific. The machine running the scanning is located in the same region as the machine being scanned."*

For an AWS Outpost, the "region" is a customer's data center. Tenable has no scanner deployment there. The assumption of reachability breaks entirely.

**Data sovereignty scenarios**

**Scenario A — Outpost with Direct Connect**
- Company has AWS Outpost in Charlotte data center with Direct Connect back to AWS us-east-1
- Risk: Scan metadata travels Charlotte → us-east-1
- May violate data residency requirements even though the underlying data stays local

**Scenario B — Sovereign cloud (EU)**
- EU healthcare company with data on AWS Outpost in Amsterdam
- GDPR requires data *and* metadata stay in EU
- Tenable platform is US-based — sending classification metadata outside the EU creates a compliance violation
- DSPM coverage = zero for this environment

**Scenario C — Air-gapped Outpost**
- Government or defense contractor with Outpost disconnected from the public internet
- No external scanner can reach it
- Completely outside any cloud DSPM coverage by design

**Vendor comparison for Outpost and sovereignty**

| Vendor | Outpost / Sovereignty |
|---|---|
| Tenable | Limited — regional scanner, sovereignty gaps |
| Cyera | Cloud-native, similar limitations |
| BigID | On-prem connector, better sovereignty story |
| AWS Macie | Native to Outpost but S3 only |
| Privacera | Built for hybrid governance including Outpost |

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
  "alternative_coverage": "AWS Macie (S3 only)"
}
```

**Example finding this unlocks**

```
FIND-013 | HIGH | DSPM Coverage Gap — Sovereignty Boundary

Datastore contains PHI subject to GDPR jurisdiction.
External DSPM scanning would require metadata to transit outside
the EU — violating data residency policy.

Current coverage: None
Recommended action: Deploy Macie natively within Outpost for S3.
Evaluate BigID on-prem connector for RDS workloads.
```

**Interview talking point**

Cloud-native DSPM tools assume the scanner can reach the data and send telemetry back to a central platform. AWS Outpost with sovereignty requirements breaks both assumptions. The data is on AWS infrastructure but physically inside a regulated boundary — even metadata about what is in the bucket may not leave that boundary. This is a growing gap as regulated industries adopt Outpost for exactly this reason.
