# AWS Secure Architecture — Healthcare & Finance

> **Enterprise-grade, compliance-first AWS infrastructure for healthcare and financial services clients.**
> Zero-trust security, HIPAA/PCI-DSS/SOX/NIST compliance, fully automated IaC with GitOps CI/CD.

---

## Table of Contents

- [Overview](#overview)
- [Architecture Diagram](#architecture-diagram)
- [Compliance Coverage](#compliance-coverage)
- [Infrastructure Stack](#infrastructure-stack)
- [Repository Structure](#repository-structure)
- [Terraform Modules](#terraform-modules)
- [Kubernetes Security](#kubernetes-security)
- [CI/CD Security Pipeline](#cicd-security-pipeline)
- [Security Controls Summary](#security-controls-summary)
- [Getting Started](#getting-started)
- [Healthcare (HIPAA) Considerations](#healthcare-hipaa-considerations)
- [Finance (PCI-DSS / SOX) Considerations](#finance-pci-dss--sox-considerations)
- [Disaster Recovery](#disaster-recovery)

---

## Overview

This repository contains complete Infrastructure as Code (IaC), Kubernetes manifests, and CI/CD pipelines for a production-grade AWS architecture designed to serve **healthcare** and **financial services** clients simultaneously — with strict regulatory compliance built in at every layer.

```
┌─────────────────────────────────────────────────────────┐
│                    CloudFront + WAF v2                   │
│         (OAC · Bot Control · Rate Limiting · Geo)        │
├─────────────────────────────────────────────────────────┤
│              Application Load Balancer (TLS 1.3)         │
├──────────────┬──────────────────────────────────────────┤
│   Public     │  Management  │  Private  │  Data  │  CDE │
│   Subnets    │   Subnets    │  Subnets  │Subnets │Subnet│
│  (NAT/ALB)   │  (CloudHSM)  │   (EKS)   │ (RDS)  │ (PAN)│
├──────────────┴──────────────────────────────────────────┤
│        AWS Network Firewall  +  Route 53 DNS Firewall    │
│                  (Suricata IDS/IPS Rules)                 │
└─────────────────────────────────────────────────────────┘
```

**Key design principles:**
- **Zero-trust networking** — deny-all defaults, explicit allows only
- **Defense in depth** — 7 security layers from DNS to runtime
- **Least privilege** — IRSA pod-level IAM, permission boundaries on every role
- **Immutable infrastructure** — Bottlerocket OS nodes, immutable ECR tags, GitOps-only deploys
- **Compliance as code** — AWS Config conformance packs, OPA Gatekeeper, Kyverno policies

---

## Architecture Diagram

Open the interactive architecture diagram in your browser:

```bash
open aws-secure-architecture.html
```

The diagram has **9 interactive tabs**:

| Tab | Contents |
|-----|----------|
| Overview | Full system architecture with all AWS services |
| Network & VPC | 5-tier subnet layout, NACLs, VPC endpoints, Transit Gateway |
| Security | WAF, GuardDuty, Security Hub, KMS key hierarchy, CloudHSM |
| CI/CD Pipeline | 11-stage security pipeline with all scanning tools |
| DevOps Stack | EKS, Karpenter, ArgoCD, Prometheus/Grafana, Falco |
| Healthcare / HIPAA | PHI data flow, SMART on FHIR, break-glass procedure |
| Finance / PCI-DSS | CDE isolation, PAN tokenization, CloudHSM dual control |
| Compliance | Controls matrix — HIPAA, PCI, SOX, CIS, NIST, GDPR |
| IR & DR | 6 Step Functions IR playbooks, 4-tier RTO/RPO, multi-region |

---

## Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| **HIPAA / HITECH** | §164.308 (Administrative), §164.310 (Physical), §164.312 (Technical) |
| **PCI-DSS v4.0** | All 12 Requirements — CDE isolation, PAN tokenization, FIM |
| **SOX ITGC** | Change management, SoD enforcement, audit trail, access review |
| **GLBA Safeguards Rule** | Data encryption, access controls, risk assessment |
| **CIS AWS Benchmark v2** | All CIS Level 1 & 2 controls — 15 CloudWatch alarms |
| **NIST SP 800-53 Rev 5** | AC, AU, CA, CM, IA, IR, SC, SI control families |
| **NIST SP 800-207** | Zero-trust architecture principles |
| **SOC 2 Type II** | CC controls mapped to AWS services |
| **ISO 27001** | Annex A controls |
| **GDPR** | Article 25, 32 — data protection by design |
| **FFIEC** | IT examination handbook controls |
| **FIPS 140-2 Level 3** | CloudHSM-backed CMKs for PHI and PAN |

---

## Infrastructure Stack

### AWS Services

```
Compute & Containers        Data & Caching              Security & Compliance
─────────────────────       ─────────────────────       ─────────────────────
EKS 1.30 (Bottlerocket)     Aurora PostgreSQL 16 SV2    KMS (7 CMKs)
Karpenter (autoscaler)      ElastiCache Redis 7.1       CloudHSM (FIPS L3)
AWS Lambda                  DynamoDB (Global Tables)    GuardDuty (all features)
EC2 (Nitro Enclaves)        OpenSearch 2.13             Security Hub (4 standards)
ECR (immutable tags)        S3 (Object Lock WORM)       CloudTrail (org trail)
                                                        AWS Config (conformance packs)
Networking                  Messaging                   Inspector V2
─────────────────────       ─────────────────────       Macie (PHI scanning)
VPC (5-tier subnets)        SQS (FIFO + DLQ)            Detective
CloudFront (OAC)            SNS (KMS encrypted)         Firewall Manager
ALB (TLS 1.3)               EventBridge                 Access Analyzer
Route 53 + DNS Firewall     Step Functions (IR)         IAM Identity Center
Network Firewall            Kinesis Firehose             Audit Manager
WAF v2 (11 rules)           API Gateway                 AWS Control Tower
Shield Advanced

Monitoring                  CI/CD & GitOps              Healthcare
─────────────────────       ─────────────────────       ─────────────────────
AMP (Managed Prometheus)    GitHub Actions (11 stages)  AWS HealthLake (FHIR R4)
AMG (Managed Grafana)       ArgoCD (App-of-Apps)        Cognito (SMART on FHIR)
AWS X-Ray                   Argo Rollouts (canary)      AWS Private CA
ADOT Collector              Cosign / Sigstore (SLSA L3) Lake Formation
CloudWatch Synthetics       Trivy / Snyk / Checkov      Amazon Fraud Detector
CloudWatch RUM              Semgrep / CodeQL / ZAP
FluentBit → CloudWatch
PagerDuty integration
```

### KMS Key Hierarchy

```
CloudHSM Cluster (FIPS 140-2 L3)
    ├── PHI CMK         → HealthLake, S3-PHI, RDS (HIPAA §164.312)
    └── PAN CMK         → CDE subnet resources only (PCI Req 3.5)

AWS KMS
    ├── App CMK         → DynamoDB, ElastiCache, SQS, general app data
    ├── Secrets CMK     → Secrets Manager (90-day rotation)
    ├── CloudTrail CMK  → CloudTrail logs + CIS 3.7 guard
    ├── EKS CMK         → Kubernetes secrets envelope encryption
    └── TFState CMK     → Terraform remote state
```

---

## Repository Structure

```
Architecture/
├── aws-secure-architecture.html        # Interactive 9-tab architecture diagram
│
├── infrastructure/
│   └── terraform/
│       ├── terragrunt.hcl              # Root Terragrunt config (multi-account)
│       ├── modules/
│       │   ├── vpc/                    # 5-tier VPC, NACLs, VPC endpoints
│       │   ├── kms/                    # 7 CMKs with CloudHSM backing
│       │   ├── cloudhsm/               # FIPS 140-2 L3 cluster, 3 nodes
│       │   ├── eks/                    # EKS 1.30, Bottlerocket, Karpenter
│       │   ├── security-groups/        # 11 SGs, deny-all defaults
│       │   ├── rds-aurora/             # Aurora PG16 Serverless v2 + Proxy
│       │   ├── elasticache/            # Redis 7.1, TLS, AUTH, cluster mode
│       │   ├── opensearch/             # OpenSearch 2.13, FGAC, SAML
│       │   ├── dynamodb/               # Global Tables, PITR, KMS
│       │   ├── s3/                     # Object Lock, replication, Macie
│       │   ├── ecr/                    # Immutable tags, Inspector V2
│       │   ├── cloudfront/             # OAC, security headers, geo-restrict
│       │   ├── waf/                    # 11 rules, Bot Control, rate limiting
│       │   ├── network-firewall/       # Suricata IDS/IPS, domain allowlist
│       │   ├── guardduty/              # All features + IR Step Functions
│       │   ├── security-hub/           # CIS, PCI, NIST, FSBP standards
│       │   ├── cloudtrail/             # Org trail, WORM, 15 CIS alarms
│       │   ├── config-rules/           # HIPAA + PCI conformance packs
│       │   ├── cognito/                # MFA, FIDO2, SMART on FHIR
│       │   ├── iam/                    # IRSA roles, boundaries, break-glass
│       │   ├── monitoring/             # AMP, AMG, Synthetics, PagerDuty
│       │   ├── backup/                 # 3-2-1-1 rule, Vault Lock, 7yr retain
│       │   └── sqs-sns/               # KMS encrypted, DLQs, TLS policies
│       └── environments/
│           └── production/             # Orchestrates all modules
│               ├── main.tf             # Full production wiring
│               ├── variables.tf
│               └── outputs.tf
│
├── kubernetes/
│   ├── karpenter/
│   │   └── nodepool.yaml              # NodePool + EC2NodeClass (Bottlerocket)
│   ├── security/
│   │   ├── kyverno/
│   │   │   └── policies.yaml          # 10 policies — signed images, rootfs, caps
│   │   ├── network-policies/
│   │   │   └── default-deny.yaml      # Zero-trust deny-all + explicit allows
│   │   └── falco/
│   │       └── custom-rules.yaml      # 14 HIPAA/PCI runtime rules
│   ├── external-secrets/
│   │   └── cluster-secret-store.yaml  # ESO → Secrets Manager sync
│   └── cert-manager/
│       └── cluster-issuer.yaml        # AWS Private CA + mTLS certificates
│
└── cicd/
    └── .github/workflows/
        └── security-pipeline.yml      # 11-stage security pipeline
```

---

## Terraform Modules

### Quick Reference

| Module | Resources | Compliance |
|--------|-----------|------------|
| `vpc` | VPC, 15 subnets/3AZ, 20+ endpoints, NACLs, Flow Logs | CIS 3.x, HIPAA §164.312 |
| `kms` | 7 CMKs, CloudHSM key store, 90/365-day rotation | PCI Req 3.5, HIPAA §164.312(a)(2)(iv) |
| `cloudhsm` | 3-node cluster, custom key store | FIPS 140-2 L3, PCI Req 3.5 |
| `eks` | Private endpoint, Bottlerocket, IRSA, OIDC | CIS EKS, NIST 800-190 |
| `security-groups` | 11 SGs — ALB, EKS, RDS, Redis, CloudHSM, CDE | PCI Req 1.3 |
| `rds-aurora` | PG16 SV2, pgaudit, IAM auth, RDS Proxy, 35d PITR | HIPAA §164.312, PCI Req 8 |
| `elasticache` | Redis 7.1 TLS/6380, AUTH rotation, cluster mode | PCI Req 2.2 |
| `opensearch` | FGAC, SAML, VPC-only, TLS 1.2 PFS, audit logs | HIPAA §164.312 |
| `dynamodb` | PITR, Global Tables, KMS, deletion protection | PCI Req 3.5 |
| `s3` | Object Lock WORM, CRR, Macie PHI scan, lifecycle | HIPAA §164.312(c) |
| `ecr` | Immutable tags, Inspector V2, pull-through cache | PCI Req 6.3 |
| `cloudfront` | OAC, WAF, CSP/HSTS headers, geo-restrict, HTTPS-only | PCI Req 6.4 |
| `waf` | 11 rules: OWASP, Bot Control, SQLi, rate limit, geo | PCI Req 6.4, HIPAA §164.312(e) |
| `network-firewall` | Suricata IDS/IPS, domain allowlist, AWS threat intel | HIPAA §164.312(e)(1), PCI Req 1.3 |
| `guardduty` | EKS/ECS/Lambda/RDS/S3/Malware + IR automation | CIS 2.x, HIPAA §164.308(a)(6) |
| `security-hub` | CIS 2.0, PCI DSS, NIST 800-53, FSBP + insights | HIPAA §164.308(a)(1) |
| `cloudtrail` | Org trail, Object Lock, 15 CIS CloudWatch alarms | CIS 3.1–3.15, PCI Req 10 |
| `config-rules` | HIPAA + PCI conformance packs, 25+ rules | HIPAA §164.308(a)(8) |
| `cognito` | MFA required, FIDO2/WebAuthn, SMART on FHIR | HIPAA §164.312(d), PCI Req 8 |
| `iam` | IRSA, permission boundaries, break-glass, analyzer | HIPAA §164.312(a)(1), PCI Req 7 |
| `monitoring` | AMP, AMG, ADOT, Synthetics, PagerDuty | HIPAA §164.308(a)(6)(ii), PCI Req 10.6 |
| `backup` | 3-2-1-1, Vault Lock, cross-region, 7yr retention | HIPAA §164.308(a)(7), PCI Req 9.8 |
| `sqs-sns` | KMS, DLQs, TLS-enforce bucket policies | HIPAA §164.312(e), PCI Req 4 |

---

## Kubernetes Security

### Pod Security — Layered Approach

```
Layer 1: Kyverno Admission Policies (10 enforced policies)
  ✓ Cosign-signed images only (Sigstore keyless + SLSA L3)
  ✓ ECR registry allowlist (no Docker Hub in prod)
  ✓ Read-only root filesystem required
  ✓ Non-root user required (UID > 0)
  ✓ ALL Linux capabilities dropped
  ✓ No privileged containers
  ✓ No hostNetwork/hostPID/hostIPC
  ✓ No hostPath mounts
  ✓ CPU + memory limits required
  ✓ PHI blocked from ConfigMaps

Layer 2: Kubernetes Network Policies (Cilium eBPF)
  ✓ Default deny-all ingress + egress per namespace
  ✓ Explicit allows: ALB → app:8080, app → RDS:5432
  ✓ Redis TLS port (6380), DNS (53), VPC endpoints (443)
  ✓ Prometheus scrape allow (monitoring ns → app ns)

Layer 3: Falco Runtime Detection (14 custom rules)
  ✓ Unauthorized PHI file access → CRITICAL alert
  ✓ PCI CDE credential access → CRITICAL alert
  ✓ Shell spawned in container → CRITICAL alert (RCE)
  ✓ Unexpected outbound connections
  ✓ Crypto mining detection
  ✓ Container escape attempts
  ✓ Bulk data export (exfiltration)
  ✓ Kubernetes admin tools in containers

Layer 4: Node Hardening (Bottlerocket + Karpenter)
  ✓ IMDSv2 hop-limit=1 (blocks pod IMDS access)
  ✓ Kernel lockdown=integrity
  ✓ sysctl: rp_filter, syncookies, no ICMP redirects
  ✓ No SSH / admin container disabled
  ✓ 30-day node rotation (expireAfter: 720h)
  ✓ Encrypted EBS volumes (root + data)
```

---

## CI/CD Security Pipeline

**11 stages** — every commit blocked on failure:

```
┌──────────────────────────────────────────────────────────────────┐
│  git push / PR                                                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 1: Secret Scanning                      │
        │  Gitleaks (git history) · TruffleHog (entropy) │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 2: SAST                                  │
        │  CodeQL · Semgrep (OWASP) · SonarQube Gate     │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 3: SCA / Dependency Check               │
        │  Snyk · OWASP Dependency-Check · pip-audit     │
        │  License compliance check                       │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 4: IaC Security                         │
        │  Checkov · tfsec · OPA Conftest · Trivy IaC    │
        │  terraform fmt/validate                         │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 5: Build (Docker Buildx multi-platform)  │
        │  SLSA provenance attached · SBOM in image       │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 6: Container Scanning                    │
        │  Trivy (OS+libs+secrets) · Snyk Container       │
        │  ECR native scan (block on CRITICAL)            │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 7: SBOM Generation                       │
        │  Syft → CycloneDX JSON + SPDX JSON             │
        │  Archived to S3 (7-year retention)              │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 8: Image Signing (SLSA L3)              │
        │  Cosign keyless (GitHub OIDC → Sigstore)        │
        │  SBOM attestation · Provenance attestation      │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 9: DAST (develop branch only)            │
        │  OWASP ZAP full scan · Nuclei CVE scan          │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 10: Compliance Gate                      │
        │  All stages must pass · Report to Security Hub  │
        │  Compliance report archived to S3               │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │  Stage 11: Deploy                               │
        │  Staging: Helm + smoke tests                    │
        │  Production: Canary 5% → monitor 5min → 100%   │
        │  Auto-rollback on error rate > 1%               │
        └───────────────────────────────────────────────┘
```

---

## Security Controls Summary

### Network Security
| Control | Implementation |
|---------|---------------|
| Perimeter WAF | WAF v2 — 11 rules, OWASP Top 10, Bot Control, SQLi |
| DDoS Protection | Shield Advanced + WAF rate limiting (2000 req/5min) |
| Network IDS/IPS | AWS Network Firewall — Suricata rules, PHI exfiltration detect |
| DNS Security | Route 53 DNS Firewall — block malicious domains |
| TLS Everywhere | TLS 1.2 minimum, TLS 1.3 preferred, no self-signed in prod |
| Micro-segmentation | 11 Security Groups + Cilium NetworkPolicy + NACLs |
| Egress Filtering | Network Firewall domain allowlist — block unexpected outbound |

### Identity & Access
| Control | Implementation |
|---------|---------------|
| Zero-standing privileges | IRSA — pod-level IAM, time-limited credentials |
| MFA everywhere | Cognito (required), AWS Console (required), Break-glass (MFA + ExternalId) |
| Least privilege | Permission boundaries on all developer-created roles |
| Privilege escalation prevention | Permission boundary denies IAM write actions |
| Break-glass | Dual-control IAM role — MFA + ExternalId + CloudWatch alarm |
| Access review | IAM Access Analyzer (org-level) + unused access analyzer (90-day) |
| SoD enforcement | Separate IAM roles per function; SOX reviewer can't deploy |

### Data Protection
| Control | Implementation |
|---------|---------------|
| PHI encryption | CloudHSM-backed CMK (FIPS 140-2 L3), KMS ViaService |
| PAN tokenization | CloudHSM-backed PAN CMK, CDE subnet isolation |
| Encryption at rest | KMS on: RDS, S3, DynamoDB, Redis, OpenSearch, EKS secrets |
| Encryption in transit | TLS 1.2+ everywhere, mTLS (cert-manager + AWS Private CA) |
| Data classification | Macie automated PHI discovery, resource tagging |
| WORM immutability | S3 Object Lock (Compliance mode, 7 years), CloudTrail Object Lock |
| Key rotation | Secrets CMK: 90 days; All others: 365 days |

### Threat Detection & Response
| Control | Implementation |
|---------|---------------|
| Cloud-native detection | GuardDuty — EKS/ECS/Lambda/RDS/S3/Malware/Credentials |
| Compliance posture | Security Hub — CIS 2.0, PCI DSS, NIST 800-53, FSBP |
| Runtime detection | Falco (eBPF) — 14 custom HIPAA/PCI rules |
| Configuration drift | AWS Config — 25+ rules, HIPAA + PCI conformance packs |
| Anomaly detection | CloudTrail Lake + CloudWatch metric filters (15 CIS alarms) |
| Incident response | Step Functions IR playbooks — isolate, snapshot, notify, terminate |
| Forensics | GuardDuty malware scan (EBS), CloudTrail data events, VPC Flow Logs |

---

## Getting Started

### Prerequisites

```bash
# Required tools
terraform  >= 1.7.0
terragrunt >= 0.55.0
aws-cli    >= 2.15.0
kubectl    >= 1.30.0
helm       >= 3.14.0
cosign     >= 2.2.0
```

### 1. Configure AWS credentials

```bash
aws configure --profile production
export AWS_PROFILE=production
```

### 2. Bootstrap Terraform remote state

```bash
# Create S3 bucket + DynamoDB lock table first
aws s3api create-bucket \
  --bucket myapp-terraform-state-production \
  --region us-east-1

aws s3api put-bucket-encryption \
  --bucket myapp-terraform-state-production \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
  }'

aws dynamodb create-table \
  --table-name myapp-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### 3. Initialize CloudHSM (prerequisite for KMS)

```bash
# CloudHSM must be initialized before KMS custom key store can connect
# See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html

cd infrastructure/terraform/modules/cloudhsm
terraform init && terraform apply

# After cluster initializes:
# 1. Download cluster CSR
# 2. Sign with your CA
# 3. Upload certificate
# 4. Initialize HSM with cloudhsm_mgmt_util
# 5. Connect custom key store:
aws kms connect-custom-key-store \
  --custom-key-store-id <id-from-output>
```

### 4. Deploy production environment

```bash
cd infrastructure/terraform/environments/production

# Review planned changes
terraform init
terraform plan -var-file=production.tfvars

# Apply (takes ~25-30 minutes)
terraform apply -var-file=production.tfvars
```

### 5. Install Kubernetes add-ons

```bash
# Update kubeconfig
aws eks update-kubeconfig --name myapp-prod --region us-east-1

# Install Karpenter
helm install karpenter oci://public.ecr.aws/karpenter/karpenter \
  --namespace kube-system \
  --set settings.clusterName=myapp-prod

# Apply NodePool
kubectl apply -f kubernetes/karpenter/nodepool.yaml

# Install External Secrets Operator
helm install external-secrets \
  external-secrets/external-secrets \
  --namespace external-secrets --create-namespace

kubectl apply -f kubernetes/external-secrets/cluster-secret-store.yaml

# Install cert-manager
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true

kubectl apply -f kubernetes/cert-manager/cluster-issuer.yaml

# Install Kyverno
helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace

kubectl apply -f kubernetes/security/kyverno/policies.yaml

# Install Falco
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf

kubectl apply -f kubernetes/security/falco/custom-rules.yaml

# Apply Network Policies
kubectl apply -f kubernetes/security/network-policies/default-deny.yaml
```

### 6. Configure GitHub Actions secrets

```bash
# Required secrets in your GitHub repository:
AWS_ACCOUNT_ID          # AWS account ID
SONAR_TOKEN             # SonarQube token
SONAR_HOST_URL          # SonarQube URL
SNYK_TOKEN              # Snyk API token
SEMGREP_APP_TOKEN       # Semgrep Cloud token
GITLEAKS_LICENSE        # Gitleaks Enterprise license
COMPLIANCE_BUCKET       # S3 bucket for compliance artifacts
SECURITY_SNS_ARN        # SNS topic for security alerts
PAGERDUTY_ENDPOINT      # PagerDuty integration URL
```

---

## Healthcare (HIPAA) Considerations

### PHI Data Flow

```
Patient App (SMART on FHIR)
    │ OAuth2 Authorization Code + PKCE
    ▼
Cognito User Pool (MFA required, FIDO2)
    │ JWT with patient context
    ▼
API Gateway (HTTPS-only)
    │ Lambda authorizer validates SMART scopes
    ▼
EKS Backend (IRSA — limited to PHI CMK ViaService)
    │ KMS decrypt via CloudHSM-backed CMK
    ▼
Aurora PostgreSQL (pgaudit — logs every query)
    │ RDS Proxy (IAM auth required)
    ▼
AWS HealthLake (FHIR R4 data store)
```

### Key HIPAA Controls
- **BAA** — AWS BAA covers all services used for PHI processing
- **PHI CMK** — CloudHSM-backed (FIPS 140-2 L3), MFA required for key management
- **Audit logging** — Every PHI access logged: pgaudit, CloudTrail data events, Macie
- **De-identification** — Safe Harbor §164.514(b) — 18 identifiers removed
- **Break-glass** — Emergency access role with MFA + ExternalId + dual-control alarm
- **Breach notification** — GuardDuty + Security Hub → SNS → 60-day HIPAA timeline
- **Minimum necessary** — IRSA scoped to specific patient records, not full table
- **Consent management** — SMART on FHIR launch context in Cognito user attributes

---

## Finance (PCI-DSS / SOX) Considerations

### CDE Architecture

```
Internet
    │
WAF v2 (PCI Req 6.4)
    │
Payment Proxy (dedicated SG — only allowed payment processor CIDRs)
    │
CDE Subnet (isolated NACL — deny-all except payment processor IPs)
    │
PAN Processing Service (CloudHSM-backed PAN CMK)
    │
Aurora PostgreSQL CDE schema (tokenized PANs only)
```

### Key PCI-DSS Controls

| Requirement | Implementation |
|-------------|---------------|
| Req 1: Firewall | VPC NACL + Security Groups + Network Firewall |
| Req 2: No defaults | Checkov/tfsec fail-open detection, Bottlerocket no-default-creds |
| Req 3: Protect PANs | CloudHSM FPE tokenization, PAN CMK ViaService |
| Req 4: Encrypt transit | TLS 1.2+, mTLS, no cleartext (Suricata PAN detect) |
| Req 5: Anti-malware | GuardDuty malware scan, Falco runtime, Inspector V2 |
| Req 6: Secure systems | SAST/SCA/DAST pipeline, immutable ECR tags, Kyverno |
| Req 7: Access control | IRSA least-privilege, permission boundaries, RBAC |
| Req 8: Authentication | MFA required (Cognito + Console), no shared accounts |
| Req 9: Physical | AWS Managed (SOC 2 Type II) |
| Req 10: Logging | CloudTrail + pgaudit + VPC Flow Logs + WAF logs (7 years) |
| Req 11: Testing | Trivy + ZAP + Nuclei in pipeline, GuardDuty continuous |
| Req 12: Policy | AWS Audit Manager, Config conformance packs |

### SOX Controls
- **SoD** — IAM roles enforce separation: developers cannot approve their own deployments
- **Change control** — GitHub branch protection (2 approvers), ArgoCD GitOps only
- **Audit trail** — CloudTrail Object Lock (WORM), 7-year retention, integrity validation
- **Access review** — IAM Access Analyzer unused access report (quarterly)
- **Financial data FIM** — Falco rule detects unauthorized modifications

---

## Disaster Recovery

### Multi-Region Architecture

```
Primary: us-east-1          DR: us-west-2
─────────────────           ─────────────────
Aurora Global DB ──────────► Aurora Global DB
  RPO: < 1 second             (read replica)

DynamoDB Global ───────────► DynamoDB Global
  Tables (Active-Active)       Tables

S3 Cross-Region ───────────► S3 Replica
  Replication (15min RTO)      (Object Lock)

ECR Replication ───────────► ECR Mirror

Backup Vault ──────────────► DR Backup Vault
  (Vault Lock WORM)            (Vault Lock WORM)
```

### RTO / RPO Tiers

| Tier | Workload | RTO | RPO |
|------|----------|-----|-----|
| Tier 1 | Critical patient data, payment processing | < 1 hour | < 1 second |
| Tier 2 | Core application services | < 4 hours | < 15 minutes |
| Tier 3 | Analytics, reporting | < 24 hours | < 1 hour |
| Tier 4 | Dev/staging environments | < 72 hours | < 24 hours |

### Regulatory Notification Timelines

| Regulation | Breach Notification Deadline |
|------------|------------------------------|
| HIPAA | 60 days (HHS) + 60 days (individuals) |
| PCI-DSS | 24 hours (card brands) |
| GLBA | 30 days (banking regulators) |
| SEC Rule | 4 business days (Form 8-K) |
| GDPR | 72 hours (supervisory authority) |
| State laws | 30-90 days (varies by state) |

---

## Contributing

1. All PRs require 2 approvals (SOX SoD)
2. Security pipeline must pass all 11 stages
3. IaC changes require Checkov + tfsec pass
4. New secrets must go through Secrets Manager (never `.env` or ConfigMaps)
5. Container images must be signed with Cosign before promotion to production

---

## License

Proprietary — All rights reserved.

---

*Built with security-first principles for healthcare and financial services workloads.*
*Compliant with HIPAA, PCI-DSS v4.0, SOX, NIST 800-53 Rev 5, CIS AWS Benchmark v2.*
