# IAM Attack Path Visualizer

**Automated detection of privilege escalation paths in AWS IAM**

## 🎯 The Problem

Organizations often have "shadow administrators" - users who can gain admin privileges through:
- Cross-account role assumption chains
- Nested IAM group memberships
- Overly permissive trust policies
- Service role misconfigurations

These hidden paths bypass traditional access reviews and create security blind spots.

## 🔍 What This Tool Does

Scans AWS IAM and generates visual attack graphs showing:
- All paths from users → admin access
- Cross-account privilege escalation
- Role assumption chains (User → Role A → Role B → Admin)
- Risk scoring based on path complexity

## 📊 Example Output

[Screenshot coming soon]

## 🛠️ Technical Details

**Built with:**
- Python 3.10+
- boto3 (AWS API)
- NetworkX (graph analysis)
- Matplotlib (visualization)

**Demonstrates:**
- Cross-account IAM analysis
- Trust policy parsing
- Graph theory application to security
- Automated risk assessment

## 🚀 Quick Start

[Coming soon]

## 👤 Author

Built by Darius Frank as part of career development in Identity & Access Management.

[GitHub Portfolio](https://github.com/Dfrank77/security-learning-artifacts)
