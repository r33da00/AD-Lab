# DCSync Attack – Mitigation

## Mitigation Strategies

### 1. Restrict Replication Permissions
- Audit accounts with:
  - `DS-Replication-Get-Changes`
  - `DS-Replication-Get-Changes-All`
- Remove unnecessary replication rights

### 2. Monitor Replication Activity
- Alert on replication requests from non-DC systems
- Log and review replication permission usage

### 3. Secure the `krbtgt` Account
- Rotate the `krbtgt` password regularly
- Perform **two password resets**, at least 24 hours apart

### 4. Privileged Access Management (PAM)
- Use Just-In-Time access for Domain Admin privileges
- Reduce standing privileged accounts

### 5. Enable Advanced Auditing
- Enable detailed Directory Service Access auditing
- Forward logs to a SIEM for correlation

### 6. Network Segmentation
- Restrict Domain Controller access
- Limit replication traffic to authorized systems only

## Defensive Takeaway

DCSync prevention is primarily a **permissions and monitoring problem**, not a tooling problem.  
Reducing replication rights and improving visibility are the most effective defenses.