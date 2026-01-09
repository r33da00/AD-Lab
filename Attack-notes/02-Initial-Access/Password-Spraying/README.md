# Credential Attacks and Password Spraying

## Overview

This phase focuses on credential-based attacks targeting low-privilege user accounts. Successfully compromising even limited accounts can provide valuable domain intelligence and serve as a foothold for further enumeration and lateral movement.

## Preparation

### Step 1: Create Wordlists

Prepare two wordlists on your attack machine:
- `users.txt` - List of potential usernames
- `passwords.txt` - List of common passwords

**Sources:**
- Generate from common naming conventions (firstname.lastname, etc.)
- Extract from OSINT gathering
- Use curated wordlists (SecLists, custom lists)
- Manually craft based on target organization

## Tool Setup: CrackMapExec

### Installation and Documentation

We'll use CrackMapExec (CME) for credential attacks. For installation instructions and detailed documentation:

**Official Documentation:** https://www.kali.org/tools/crackmapexec/

```bash
# Install on Kali Linux
sudo apt update
sudo apt install crackmapexec
```

**Alternative:** NetExec is a modern fork of CrackMapExec with additional features and active development.

## Attack Execution

### Step 1: Initial Reconnaissance

Gather basic information about the target domain controller:

```bash
crackmapexec smb <DC_IP>
```

**Information Retrieved:**
- Operating system version
- Hostname
- Domain name
- SMB signing status
- Protocol version

### Step 2: Password Spraying Attack

Password spraying attempts a single password (or small set of passwords) against multiple user accounts, avoiding account lockouts.

#### Single Password Spray

```bash
crackmapexec smb <DC_IP> -u users.txt -p 'Password123!'
```

**Best Practices:**
- Use common organizational passwords (Welcome2024, Company123!, etc.)
- Respect lockout policies (check first with `--pass-pol`)
- Space out attempts to avoid detection
- Target 1-3 passwords per spray cycle

#### Multiple Password Spray

```bash
crackmapexec smb <DC_IP> -u users.txt -p passwords.txt
```

**Success Indicators:**
- `[+]` symbol indicates valid credentials
- Credentials displayed in format: `DOMAIN\username:password`

### Step 3: Post-Compromise Enumeration

Once valid credentials are obtained, leverage them for additional reconnaissance.

#### Enumerate Password Policy

```bash
crackmapexec smb <DC_IP> -u <username> -p <password> --pass-pol
```

**Retrieved Information:**
- Minimum password length
- Password complexity requirements
- Lockout threshold
- Lockout duration
- Password history count
- Maximum password age

This intelligence helps refine future credential attacks and avoid lockouts.

#### Enumerate Local Groups

```bash
crackmapexec smb <DC_IP> -u <username> -p <password> --local-groups
```

**Output:** Lists local groups on the target system, revealing potential privilege escalation paths.

## Additional CrackMapExec Capabilities

CrackMapExec offers extensive post-authentication enumeration features:

```bash
# Enumerate domain users
crackmapexec smb <DC_IP> -u <username> -p <password> --users

# Enumerate domain groups
crackmapexec smb <DC_IP> -u <username> -p <password> --groups

# Enumerate logged-on users
crackmapexec smb <DC_IP> -u <username> -p <password> --loggedon-users

# Enumerate shares
crackmapexec smb <DC_IP> -u <username> -p <password> --shares

# Check if user has admin access
crackmapexec smb <DC_IP> -u <username> -p <password>
# Look for (Pwn3d!) indicator
```

## Tool Comparison: CrackMapExec vs NetExec

**CrackMapExec:**
- Established, widely documented
- Large community support
- Stable and reliable

**NetExec:**
- Active development and updates
- Enhanced features and protocols
- Improved performance
- Compatible CME syntax

**Recommendation:** Familiarize yourself with both tools to leverage their respective strengths.

## Key Takeaways

The primary objective of this phase is obtaining **valid domain credentials**, which enable:
- BloodHound enumeration (next phase)
- SMB share access
- Additional authenticated scans
- Lateral movement opportunities
- Privilege escalation paths

## Operational Security Considerations

- **Account Lockouts:** Always enumerate password policies before spraying
- **Detection:** Password spraying can trigger security alerts; pace your attacks
- **Logging:** Assume all authentication attempts are logged
- **Noise Level:** Credential attacks generate significant network traffic

## Next Steps

Proceed to the **BloodHound Enumeration** phase using the credentials obtained from this attack to map Active Directory relationships and identify privilege escalation paths.

---

**Remember:** Document all discovered credentials securely and maintain detailed notes of successful attack vectors for reporting purposes.