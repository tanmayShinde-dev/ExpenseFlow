# Attack Graph Analyst Playbook
**Issue #848 - Security Analyst Quick Reference**

## Daily Operations

### 1. Morning Review

Start your shift by checking the dashboard:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/dashboard
```

**What to look for:**
- New critical/high severity incidents
- High-risk entities requiring investigation
- Unusual activity spikes in the last 24 hours

### 2. Incident Triage

List new incidents:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.expenseflow.com/api/attack-graph/incidents?status=NEW&sortBy=severity"
```

**Priority Order:**
1. Critical severity + high confidence (>80)
2. High severity + medium/high confidence (>60)
3. Medium severity incidents
4. Low severity incidents

### 3. Incident Investigation Workflow

#### Step 1: Assign to Yourself

```bash
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/assign
```

This automatically changes status from NEW → INVESTIGATING

#### Step 2: Review Incident Details

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123
```

**Key Fields to Review:**
- `confidenceScore` - How certain the system is (0-100)
- `incidentType` - Type of attack detected
- `campaignMetrics` - Scale of attack (IPs, devices, users)
- `clusteringReasoning` - Why events were grouped together
- `evidence.evidenceChain` - Timeline of events

#### Step 3: Visualize the Attack Graph

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/graph
```

**Look for:**
- Central nodes (high degree count) = key infrastructure
- Clusters of related entities
- Unusual relationship patterns
- Geographic anomalies

#### Step 4: Add Initial Observation

```bash
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Reviewing distributed credential stuffing from 12 IPs",
    "noteType": "OBSERVATION"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/notes
```

## Common Attack Patterns

### Pattern 1: Distributed Credential Stuffing

**Indicators:**
- `incidentType: DISTRIBUTED_CREDENTIAL_STUFFING`
- Multiple IPs (>=5) targeting same accounts
- Low event velocity (<20/hour)
- Extended timeframe (hours or days)

**Response Actions:**
1. Verify targeted accounts are legitimate
2. Check if credentials match known breaches
3. Blocklist attacking IPs
4. Force password reset for targeted users
5. Enable mandatory 2FA for affected accounts

**Commands:**
```bash
# Blocklist all attacking IPs
for ip_entity_id in $(cat suspicious_ips.txt); do
  curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "reason": "Distributed credential stuffing campaign",
      "expiresInHours": 168
    }' \
    https://api.expenseflow.com/api/attack-graph/entities/$ip_entity_id/blocklist
done

# Mass revoke sessions
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Incident INC-20260301-ABC123 - credential stuffing"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/revoke-sessions
```

### Pattern 2: Rapid Burst Attack

**Indicators:**
- `incidentType: RAPID_BURST_ATTACK`
- High event velocity (>50/hour)
- Short timeframe (minutes)
- Usually automated/botnet

**Response Actions:**
1. **IMMEDIATE**: Mass revoke all related sessions
2. Blocklist all attacking infrastructure
3. Check for successful logins (compromised accounts)
4. Alert affected users
5. Monitor for attack shift to new IPs

**Quick Response:**
```bash
# Immediate session revocation
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Active burst attack - immediate response"}' \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/revoke-sessions

# Update status to MITIGATED
curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "MITIGATED",
    "notes": "All sessions revoked, IPs blocklisted"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INC-20260301-ABC123/status
```

### Pattern 3: Coordinated Attack Campaign

**Indicators:**
- `incidentType: COORDINATED_ATTACK`
- High graph density (>50%)
- Multiple entity types involved
- Sophisticated patterns

**Response Actions:**
1. **DEEP INVESTIGATION**: Understand full scope
2. Identify command and control infrastructure
3. Trace attack timeline
4. Look for compromised insider accounts
5. Check for successful data exfiltration
6. May require legal/law enforcement notification

**Investigation Commands:**
```bash
# Get all high-risk entities
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.expenseflow.com/api/attack-graph/entities/high-risk?minRiskScore=80"

# For each suspicious entity, traverse the graph
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "maxDepth": 4,
    "direction": "both"
  }' \
  https://api.expenseflow.com/api/attack-graph/entities/ENTITY_ID/traverse
```

## Entity Investigation

### Investigate IP Address

```bash
# Get IP entity details
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/entities/ENTITY_ID

# Check for:
# - Recent activity (lastSeen)
# - Risk score
# - Number of failed login attempts
# - Associated incidents
# - Enrichment data (proxy, VPN, Tor)
```

**Blocklist if:**
- Risk score >80
- Multiple failed attempts (>20)
- Associated with confirmed incidents
- Known proxy/VPN/Tor exit node with suspicious activity

### Investigate Device Fingerprint

```bash
# Get device entity details
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/entities/DEVICE_ENTITY_ID
```

**Red flags:**
- Same device accessing multiple unrelated accounts
- Device metadata inconsistencies
- Rapid switching between locations
- Unusual browser/OS combinations

### Investigate User Account

```bash
# Get user entity
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/entities/USER_ENTITY_ID

# Check related events
# Look at devices and IPs used
```

**Potential compromise indicators:**
- Successful login after many failures
- Access from new device/location
- Unusual transaction patterns
- Session from high-risk IP

## Response Procedures

### Blocklist Infrastructure

**IP Address:**
```bash
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Confirmed malicious activity - [incident ID]",
    "expiresInHours": 168
  }' \
  https://api.expenseflow.com/api/attack-graph/entities/IP_ENTITY_ID/blocklist
```

**Device Fingerprint:**
```bash
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Compromised or spoofed device",
    "expiresInHours": null
  }' \
  https://api.expenseflow.com/api/attack-graph/entities/DEVICE_ENTITY_ID/blocklist
```

### Session Management

**Mass Revocation:**
```bash
# Revoke all sessions for incident
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Security incident response"}' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/revoke-sessions
```

### Incident Status Updates

**Workflow:**
1. NEW → INVESTIGATING (automatic on assignment)
2. INVESTIGATING → CONFIRMED (after verification)
3. CONFIRMED → MITIGATED (after response actions)
4. MITIGATED → RESOLVED (after monitoring period)

Or: INVESTIGATING → FALSE_POSITIVE (if benign)

**Update Status:**
```bash
curl -X PUT -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "CONFIRMED",
    "notes": "Verified attack pattern, initiated response"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/status
```

## Documentation Best Practices

### Adding Notes

Always document your investigation:

```bash
# Observation
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Detected botnet pattern using rotating residential proxies",
    "noteType": "OBSERVATION"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/notes

# Hypothesis
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Suspect compromised residential proxy network, investigating source",
    "noteType": "HYPOTHESIS"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/notes

# Action Taken
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Blocklisted 47 IP addresses, revoked 12 sessions, alerted 3 users",
    "noteType": "ACTION_TAKEN"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/notes

# Conclusion
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "note": "Attack mitigated. No data breach. Recommended enhanced monitoring for 72h",
    "noteType": "CONCLUSION"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/notes
```

### Validation for Metrics

**Important**: Always validate incidents to improve detection accuracy:

```bash
# True Positive
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "isTruePositive": true,
    "notes": "Confirmed credential stuffing campaign"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/validate

# False Positive
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "isTruePositive": false,
    "notes": "Legitimate user behavior from corporate VPN"
  }' \
  https://api.expenseflow.com/api/attack-graph/incidents/INCIDENT_ID/validate
```

## Metrics and Reporting

### Daily Metrics Review

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.expenseflow.com/api/attack-graph/metrics
```

**KPIs to Track:**
- Precision (true positives / total incidents)
- Active incident count
- Incidents by type and severity
- High-risk entity count
- Response time (detection to mitigation)

### Weekly Report

Generate weekly summary:
1. Total incidents detected
2. Incidents by type
3. Response times
4. Entities blocklisted
5. Sessions revoked
6. False positive rate
7. Trends and patterns

## Escalation Criteria

**Escalate to Senior Analyst if:**
- Critical severity + high confidence (>90)
- Attack still active after initial mitigation
- Potential data breach detected
- Insider threat suspected
- Legal/compliance implications
- Nation-state level sophistication

**Escalate to Management if:**
- Multiple critical incidents
- Widespread compromise
- Customer data at risk
- Media attention likely
- Law enforcement notification needed

## Tips and Tricks

### Quick Filters

**Today's critical incidents:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.expenseflow.com/api/attack-graph/incidents?severity=critical&status=NEW,INVESTIGATING&sortBy=confidenceScore&sortOrder=desc"
```

**High-confidence unassigned incidents:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.expenseflow.com/api/attack-graph/incidents?minConfidence=80&status=NEW"
```

**Recent false positives (learn from them):**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.expenseflow.com/api/attack-graph/incidents?status=FALSE_POSITIVE&limit=20"
```

### Graph Traversal for Attribution

To understand attack infrastructure:
1. Find central high-risk IP
2. Traverse graph depth 3-4
3. Look for ASN clustering (same provider)
4. Check temporal patterns (coordinated timing)
5. Identify C2 infrastructure patterns

### Automation Ideas

Create shell scripts for common tasks:
- Daily incident triage
- Blocklist high-risk IPs automatically
- Alert on critical incidents
- Generate weekly reports
- Monitor specific entity types

## Common Pitfalls to Avoid

❌ **Don't:**
- Mark incidents as resolved without validation
- Blocklist without investigation (especially users)
- Ignore low-confidence incidents entirely
- Forget to document your actions
- Revoke sessions during business hours without user notification

✅ **Do:**
- Validate all incidents (true/false positive)
- Document investigation findings
- Use graph visualization for complex incidents
- Check for collateral impact before blocking
- Monitor after mitigation
- Learn from false positives

## Support and Resources

- **Technical Documentation**: `ISSUE_848_IMPLEMENTATION_SUMMARY.md`
- **API Reference**: Full endpoint documentation in main docs
- **Graph Theory**: Understanding centrality, clustering
- **MITRE ATT&CK**: Map incidents to ATT&CK framework
- **Team Chat**: #security-incidents Slack channel

## Emergency Procedures

### Active Attack in Progress

1. **DO NOT WAIT** - Mass revoke sessions immediately
2. Blocklist all attacking infrastructure
3. Alert security team on emergency channel
4. Document actions in real-time
5. Prepare incident report for management

### Suspected Data Breach

1. Preserve evidence (don't delete anything)
2. Escalate immediately to senior analyst + management
3. Notify legal/compliance team
4. Follow breach response playbook
5. Prepare for potential disclosure requirements

---

**Remember**: Speed matters in incident response, but accuracy matters more. When in doubt, escalate.

**Stay Updated**: This playbook is a living document. Contribute improvements based on your experience.
