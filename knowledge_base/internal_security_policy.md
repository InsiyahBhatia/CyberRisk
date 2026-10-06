# Acme Corp Information Security Policy (SYNTHETIC DOCUMENT)

> Synthetic document created for the CyberRisk demo. Acme Corp is fictional. Not a real policy.

Framework: Internal
Version: 2.1
Source type: synthetic internal policy

## 1. Purpose and scope

This policy defines the minimum information security requirements for all employees, contractors and systems of Acme Corp. It applies to all production, staging and development environments and to all business units.

## 2. Governance and risk management

The Security Manager owns the information security programme. Risks are recorded in the risk register and scored using likelihood and impact on a 1-5 scale. Residual risk is calculated from inherent risk and the effectiveness of linked controls. Risks rated HIGH or CRITICAL after treatment must be reviewed monthly. Acceptance of a HIGH or CRITICAL risk requires documented approval by a named executive; it cannot be approved automatically or by an automated system.

## 3. Access control and authentication

Multi-factor authentication (MFA) is mandatory for all privileged accounts, all remote access, and all access to systems classified Confidential or Restricted. Standard user accounts must adopt MFA within 30 days of onboarding. Access follows least privilege and is reviewed quarterly by the system owner. Dormant accounts (no login for 90 days) are disabled.

## 4. Vulnerability and patch management

Vulnerabilities are identified by authenticated scanning at least weekly. Remediation targets by severity: CRITICAL within 15 days, HIGH within 30 days, MEDIUM within 90 days. Vulnerabilities listed in the CISA Known Exploited Vulnerabilities (KEV) catalog are treated as one severity level higher and must be remediated by the KEV due date or an approved exception. Internet-facing assets are patched first.

## 5. Logging and monitoring

Authentication events, privileged actions and security tool alerts are forwarded to the central log platform and retained for 12 months. Alerts for critical assets are triaged within 4 hours.

## 6. Data protection

Confidential and Restricted data must be encrypted at rest and in transit using approved algorithms. Production data may not be copied to non-production environments without masking.

## 7. Evidence and audit

Control owners collect evidence for each control at least annually. Evidence expires after 12 months unless the control owner documents a shorter or longer period. Expired evidence is treated as missing for compliance reporting.
