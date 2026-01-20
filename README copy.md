# AWS IAM Lab 2: IAM Access Analyzer

## Overview

Implemented AWS IAM Access Analyzer to continuously monitor for IAM security risks across the AWS Organization. This lab demonstrates operational security practices - detecting, investigating, and remediating IAM misconfigurations.

## What I Built

**Analyzer Configuration:**
- Organization-wide IAM Access Analyzer
- Continuous scanning across all accounts in the organization
- Automated finding generation for security risks

**Test Scenarios Created:**
- Publicly accessible S3 bucket (internet exposure risk)
- Investigated the finding using AWS CLI
- Analyzed root cause and remediated the issue

**Remediation Workflow:**
1. Detected public S3 bucket via Access Analyzer
2. Retrieved detailed finding information
3. Analyzed the bucket policy causing the exposure
4. Removed the public policy
5. Verified finding status changed to RESOLVED
6. Generated audit report for compliance documentation

## Skills Demonstrated

- **Security monitoring** - Continuous IAM risk detection
- **Finding investigation** - Analyzing Access Analyzer output
- **Root cause analysis** - Understanding policy evaluation
- **Remediation** - Fixing IAM misconfigurations
- **Compliance evidence** - Generating audit reports
- **Operational security** - Day-to-day security analyst work

## How IAM Access Analyzer Works

Access Analyzer uses **automated reasoning** and **provable security** to analyze resource policies:

1. **Scans resource policies** (S3 buckets, IAM roles, KMS keys, Lambda functions, etc.)
2. **Identifies external access** - Resources shared outside your organization
3. **Generates findings** - Categorizes by risk level and access type
4. **Continuous monitoring** - Automatically rescans when policies change

### Finding Types

| **Type** | **Description** | **Risk Level** |
|----------|----------------|----------------|
| 🔴 **Public** | Resource accessible to anyone on the internet | CRITICAL |
| 🟡 **External** | Resource shared with other AWS accounts | HIGH |
| 🔵 **Cross-account** | Resource shared within your organization | MEDIUM |

## Policy Evaluation Example

**S3 Bucket Policy (The Security Issue):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::darius-iam-test-1766847930/*"
  }]
}
```

**Access Analyzer Finding:**
- **Risk:** Public access (`Principal: "*"` = anyone on the internet)
- **Action:** `s3:GetObject` (anyone can read all objects)
- **Impact:** Data exposure - anyone could download files
- **Status:** ACTIVE (requires remediation)

**Remediation:**
```bash
aws s3api delete-bucket-policy --bucket darius-iam-test-1766847930
```

**Result:** Finding status changed to RESOLVED

## Real-World Application at Shopify

As a Technical Security Analyst, I would use Access Analyzer to:

### Daily Operations
- Review new findings generated overnight or in real-time
- Investigate whether external access is intentional or misconfiguration
- Work with development teams to remediate issues
- Escalate high-risk findings (public data exposure) immediately

### Compliance & Audit
- Generate quarterly reports of all findings for SOC 2 audits
- Prove to auditors that we detect and fix IAM issues continuously
- Demonstrate least-privilege enforcement
- Track metrics: time-to-remediation, findings by severity, etc.

### Incident Response
- Quickly identify if a compromised account created external access
- Find overly permissive policies that could be exploited
- Assess blast radius of a security incident
- Validate that remediation actions resolved the issue

## Commands Used
```bash
# Enable Access Analyzer (organization-wide)
aws accessanalyzer create-analyzer \
  --analyzer-name "OrgWideSecurityAnalyzer" \
  --type ORGANIZATION

# List all findings
aws accessanalyzer list-findings --analyzer-arn ARN

# Get specific finding details
aws accessanalyzer get-finding --analyzer-arn ARN --id FINDING_ID

# Filter for active findings only
aws accessanalyzer list-findings \
  --analyzer-arn ARN \
  --filter '{"status":{"eq":["ACTIVE"]}}'

# Check if finding is resolved
aws accessanalyzer get-finding \
  --analyzer-arn ARN \
  --id FINDING_ID | jq -r '.finding.status'

# Generate findings report for audit
aws accessanalyzer list-findings --analyzer-arn ARN > findings-report.json
```

## Comparison to Other Platforms

| **Platform** | **Tool** | **Detection Method** | **Frequency** |
|-------------|---------|---------------------|---------------|
| **AWS** | IAM Access Analyzer | Automated reasoning | Continuous |
| **Entra ID** | Access Reviews | Manual attestation | Quarterly |
| **Entra ID** | Sign-in Risk | ML-based detection | Real-time |
| **GCP** | Policy Analyzer | Policy evaluation | Continuous |

**Key Advantage:** Access Analyzer is **automated and continuous** vs. manual periodic reviews. It uses **provable security** (formal logic) rather than heuristics.

## Investigation Workflow

## 🔍 Visual Demonstration

### Finding Details
![Finding Details](images/finding-details.png)
*Access Analyzer detected external access to IAM role via Okta SAML provider*

### Active Findings List
![Findings List](images/findings-list.png)
*Organization-wide monitoring showing 3 active findings requiring review*


## Files in This Lab

- `findings-summary.txt` - Human-readable summary of all findings
- `access-analyzer-findings-report.json` - Full JSON report with details
- `README.md` - This documentation

## Findings Summary
```
RESOLVED | AWS::S3::Bucket | darius-iam-test-1766847930 (Public bucket - FIXED)
ACTIVE   | AWS::IAM::Role | ReadOnly-Lab (Federated access - EXPECTED)
ACTIVE   | AWS::IAM::Role | AdministratorAccess (Federated access - EXPECTED)
ACTIVE   | AWS::IAM::Role | Admin-Access-Lab (Federated access - EXPECTED)
```

**Note:** The IAM Role findings are from IAM Identity Center (SSO) integration with Okta. These are intentional federated access patterns and represent expected configuration, not security issues.

## Next Steps

- [ ] Set up automated alerting (SNS/EventBridge) for critical findings
- [ ] Create Lambda function to auto-remediate certain finding types
- [ ] Build CloudWatch dashboard for findings trends
- [ ] Integrate with SIEM for centralized security monitoring
- [ ] Implement automated response playbooks

---

**Lab Environment:** AWS Organizations with Production and Non-Production OUs  
**Region:** us-east-2  
**Tools Used:** AWS CLI, jq, IAM Access Analyzer  
**Time to Complete:** 2-3 hours  
**Skills Level:** Intermediate
