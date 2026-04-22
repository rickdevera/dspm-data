"""
company.py
Defines the fictional company: Meridian Health Analytics
A mid-size healthcare data company - chosen because it has PII, PHI, PCI,
and financial data all in one place. Rich target for DSPM scenarios.
"""

COMPANY = {
    "name": "Meridian Health Analytics",
    "industry": "Healthcare Data & Analytics",
    "size": "mid-market",
    "regions": ["us-east-1", "us-west-2", "eu-west-1"],
    "primary_region": "us-east-1"
}

# Departments drive behavior patterns and data access expectations
DEPARTMENTS = {
    "engineering": {
        "headcount": 18,
        "work_pattern": "flexible",       # 7am-10pm, heavy variance
        "base_region": "us-west-2",
        "expected_data_access": ["source_code", "logs", "dev_databases"],
        "risk_multiplier": 1.4             # engineers accumulate permissions
    },
    "data_science": {
        "headcount": 10,
        "work_pattern": "standard",
        "base_region": "us-east-1",
        "expected_data_access": ["analytics_datasets", "model_outputs", "research_data"],
        "risk_multiplier": 1.6             # data scientists want ALL the data
    },
    "finance": {
        "headcount": 8,
        "work_pattern": "early",           # 7am-6pm, spikes at quarter close
        "base_region": "us-east-1",
        "expected_data_access": ["financial_reports", "billing_data", "contracts"],
        "risk_multiplier": 1.0
    },
    "hr": {
        "headcount": 6,
        "work_pattern": "standard",
        "base_region": "us-east-1",
        "expected_data_access": ["employee_records", "payroll_data", "benefits"],
        "risk_multiplier": 0.8
    },
    "sales": {
        "headcount": 12,
        "work_pattern": "extended",        # sales works odd hours, travels
        "base_region": "us-east-1",
        "expected_data_access": ["customer_data", "contracts", "pricing"],
        "risk_multiplier": 1.2
    },
    "customer_success": {
        "headcount": 9,
        "work_pattern": "standard",
        "base_region": "us-east-1",
        "expected_data_access": ["customer_data", "support_tickets", "usage_metrics"],
        "risk_multiplier": 1.1
    },
    "legal": {
        "headcount": 4,
        "work_pattern": "standard",
        "base_region": "us-east-1",
        "expected_data_access": ["contracts", "compliance_reports", "employee_records"],
        "risk_multiplier": 0.7
    },
    "it_ops": {
        "headcount": 7,
        "work_pattern": "oncall",          # 24/7 pattern with rotation
        "base_region": "us-east-1",
        "expected_data_access": ["infrastructure_configs", "logs", "all_systems"],
        "risk_multiplier": 1.8             # IT has keys to everything
    }
}

# Datastores - these are the crown jewels DSPM cares about
DATASTORES = [
    {
        "id": "s3-patient-records",
        "name": "meridian-patient-records-prod",
        "type": "s3_bucket",
        "classification": "PHI",
        "sensitivity": "critical",
        "region": "us-east-1",
        "contains": ["patient_names", "dob", "ssn", "diagnosis_codes", "treatment_records"],
        "row_estimate": 2400000,
        "legitimate_accessors": ["data_science", "engineering"],
        "compliance": ["HIPAA", "SOC2"]
    },
    {
        "id": "s3-customer-pii",
        "name": "meridian-customer-data-prod",
        "type": "s3_bucket",
        "classification": "PII",
        "sensitivity": "high",
        "region": "us-east-1",
        "contains": ["customer_names", "emails", "phone_numbers", "addresses"],
        "row_estimate": 180000,
        "legitimate_accessors": ["sales", "customer_success", "engineering"],
        "compliance": ["GDPR", "CCPA"]
    },
    {
        "id": "rds-billing",
        "name": "meridian-billing-db-prod",
        "type": "rds_postgres",
        "classification": "PCI",
        "sensitivity": "critical",
        "region": "us-east-1",
        "contains": ["credit_card_tokens", "billing_history", "payment_methods"],
        "row_estimate": 95000,
        "legitimate_accessors": ["finance", "engineering"],
        "compliance": ["PCI-DSS", "SOC2"]
    },
    {
        "id": "s3-analytics-raw",
        "name": "meridian-analytics-raw-data",
        "type": "s3_bucket",
        "classification": "CONFIDENTIAL",
        "sensitivity": "high",
        "region": "us-west-2",
        "contains": ["aggregated_health_metrics", "de_identified_records", "model_training_data"],
        "row_estimate": 8700000,
        "legitimate_accessors": ["data_science", "engineering"],
        "compliance": ["HIPAA", "SOC2"]
    },
    {
        "id": "s3-employee-records",
        "name": "meridian-hr-documents",
        "type": "s3_bucket",
        "classification": "CONFIDENTIAL",
        "sensitivity": "high",
        "region": "us-east-1",
        "contains": ["employee_pii", "salary_data", "performance_reviews", "ssn"],
        "row_estimate": 740,
        "legitimate_accessors": ["hr", "legal", "finance"],
        "compliance": ["SOC2"]
    },
    {
        "id": "s3-financial-reports",
        "name": "meridian-finance-reports",
        "type": "s3_bucket",
        "classification": "CONFIDENTIAL",
        "sensitivity": "medium",
        "region": "us-east-1",
        "contains": ["quarterly_reports", "forecasts", "board_materials"],
        "row_estimate": 3200,
        "legitimate_accessors": ["finance", "legal"],
        "compliance": ["SOC2"]
    },
    {
        "id": "s3-dev-scratch",
        "name": "meridian-dev-scratch-pad",
        "type": "s3_bucket",
        "classification": "INTERNAL",
        "sensitivity": "medium",
        "region": "us-west-2",
        "contains": ["dev_configs", "test_data", "build_artifacts"],
        "row_estimate": 12000,
        "legitimate_accessors": ["engineering"],
        "compliance": []
    },
    {
        "id": "rds-app-prod",
        "name": "meridian-app-db-prod",
        "type": "rds_postgres",
        "classification": "PII",
        "sensitivity": "high",
        "region": "us-east-1",
        "contains": ["user_accounts", "session_data", "api_keys", "customer_profiles"],
        "row_estimate": 220000,
        "legitimate_accessors": ["engineering", "customer_success"],
        "compliance": ["SOC2", "GDPR"]
    }
]

# IAM Roles - the permission structures users get assigned
IAM_ROLES = [
    {
        "id": "role-data-scientist",
        "name": "DataScientistRole",
        "policies": ["S3ReadAll", "AthenaFullAccess", "GlueReadOnly"],
        "datastores": ["s3-analytics-raw", "s3-patient-records", "s3-customer-pii"],
        "risk_level": "high",
        "notes": "Broad S3 read is standard but grants more than most DS need"
    },
    {
        "id": "role-engineer-dev",
        "name": "EngineerDeveloperRole",
        "policies": ["S3FullAccess", "RDSReadWrite", "CloudWatchFullAccess", "IAMReadOnly"],
        "datastores": ["s3-dev-scratch", "rds-app-prod", "s3-analytics-raw"],
        "risk_level": "medium",
        "notes": "Standard dev role"
    },
    {
        "id": "role-engineer-senior",
        "name": "EngineerSeniorRole",
        "policies": ["S3FullAccess", "RDSFullAccess", "IAMPowerUser", "EC2FullAccess"],
        "datastores": ["s3-dev-scratch", "rds-app-prod", "rds-billing", "s3-analytics-raw"],
        "risk_level": "high",
        "notes": "Senior engineers can touch prod DBs"
    },
    {
        "id": "role-finance",
        "name": "FinanceAnalystRole",
        "policies": ["S3ReadOnly", "AthenaReadOnly"],
        "datastores": ["s3-financial-reports", "rds-billing"],
        "risk_level": "low",
        "notes": "Appropriately scoped"
    },
    {
        "id": "role-hr",
        "name": "HRSpecialistRole",
        "policies": ["S3ReadWrite"],
        "datastores": ["s3-employee-records"],
        "risk_level": "low",
        "notes": "Appropriately scoped"
    },
    {
        "id": "role-sales",
        "name": "SalesRepRole",
        "policies": ["S3ReadOnly", "DynamoDBReadOnly"],
        "datastores": ["s3-customer-pii"],
        "risk_level": "medium",
        "notes": "Sales accessing raw PII bucket vs CRM is a finding"
    },
    {
        "id": "role-admin",
        "name": "ITAdminRole",
        "policies": ["AdministratorAccess"],
        "datastores": ["*"],
        "risk_level": "critical",
        "notes": "Full admin - should be tightly controlled, often isn't"
    },
    {
        "id": "role-readonly",
        "name": "ReadOnlyAuditRole",
        "policies": ["ReadOnlyAccess"],
        "datastores": ["*"],
        "risk_level": "low",
        "notes": "Audit role - read everything, change nothing"
    },
    {
        "id": "role-svc-etl",
        "name": "ETLServiceRole",
        "policies": ["S3FullAccess", "RDSFullAccess", "GlueFullAccess"],
        "datastores": ["s3-patient-records", "s3-analytics-raw", "rds-app-prod", "rds-billing"],
        "risk_level": "critical",
        "notes": "Service account with excessive access - common finding"
    },
    {
        "id": "role-contractor",
        "name": "ContractorLimitedRole",
        "policies": ["S3ReadOnly"],
        "datastores": ["s3-dev-scratch"],
        "risk_level": "low",
        "notes": "Scoped contractor access - but check what they actually touch"
    }
]
