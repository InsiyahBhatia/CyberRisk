# Acme Corp Incident Response Policy (SYNTHETIC DOCUMENT)

> Synthetic document created for the CyberRisk demo. Acme Corp is fictional. Not a real policy.

Framework: Internal
Version: 1.4
Source type: synthetic internal policy

## 1. Roles

The Incident Commander directs response. The Security Analyst on duty triages alerts. The Communications Lead handles internal and external notifications. Legal must be consulted before any external notification.

## 2. Severity classification

CRITICAL: confirmed compromise of a critical asset, ransomware execution, or confirmed exfiltration of Restricted data. HIGH: confirmed compromise of a non-critical asset or active attacker presence. MEDIUM: suspicious activity requiring investigation. LOW: policy violation without evidence of compromise.

## 3. Response phases

1. Detection and triage: validate the alert, assign severity, open an incident record.
2. Containment: isolate affected hosts, disable compromised credentials, block malicious indicators. Containment actions on production systems require Incident Commander approval.
3. Eradication and recovery: remove attacker access, restore from known-good backups, validate systems before returning to service.
4. Post-incident review: complete within 10 business days of closure; record root cause, timeline, adversary techniques (mapped to MITRE ATT&CK where known) and corrective actions.

## 4. Targets

Mean time to acknowledge CRITICAL incidents: 15 minutes. Mean time to contain CRITICAL incidents: 4 hours. Incident records must include the affected asset, detection time, resolution time and ATT&CK technique identifiers where known.

## 5. Exercises

The response plan is exercised by tabletop at least twice a year. Findings from exercises are tracked as remediation actions.
