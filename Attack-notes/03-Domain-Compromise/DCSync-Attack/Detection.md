## # DCSync Attack – Detection

## Key Detection Indicators

### Windows Event Logs

- **Event ID 4662**
  - Directory Service Access with replication permissions
  - Especially suspicious when initiated by non-DC accounts

- **Event ID 5136**
  - Directory Service object modifications

### Behavioral Indicators

- Replication requests originating from non-Domain Controller hosts
- Unusual use of replication permissions by service or user accounts
- Security tool alerts identifying DCSync or secretsdump behavior

## Detection Challenges

- DCSync uses legitimate AD replication APIs
- Activity may blend with normal DC behavior
- Requires contextual analysis rather than signature-based detection

## Recommended Monitoring

- Alert on Event ID 4662 with replication GUIDs
- Baseline normal replication behavior
- Correlate replication activity with host roles