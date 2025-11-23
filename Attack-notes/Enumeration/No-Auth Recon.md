# Active Directory Enumeration Guide

## Overview
This guide demonstrates reconnaissance and enumeration techniques against an Active Directory environment using various security testing tools.

---

## 1. Initial Setup

Start your attacker machine (Ubuntu, Kali Linux, or similar penetration testing distribution).

---

## 2. Network Reconnaissance with Nmap

Launch a comprehensive Nmap scan against the Domain Controller to identify open ports, service versions, and configurations.

### Command
```bash
nmap -p- -sV -sC -sS -Pn <dc_ip> -T4 -vv -oN <outputfile_name>
```
> **Note:** This full port scan may take considerable time depending on network bandwidth and target responsiveness.

### Expected Results
The scan will reveal open ports and running services on the Domain Controller.

---

## 3. DNS Enumeration

Perform additional DNS record scanning to gather more intelligence about the domain infrastructure.

We'll use the `dig` command for DNS queries. Run `dig -h` for detailed usage information.

### 3.1 LDAP SRV Record Enumeration

Query for LDAP service records to identify LDAP servers and ports.

#### Command
```bash
dig @<dc_ip> _ldap._tcp.<domain_name> SRV
```

#### Results
This reveals:
- Domain Controller hostname
- LDAP service port (typically 389 or 636 for LDAPS)

See: `Screenshots/enumeration/DNS_enum`

#### 3.1.1 Anonymous LDAP Bind Attempt

Attempt to enumerate users, groups, and organizational units via anonymous LDAP binding.

**Tool:** `ldapsearch`

##### Command
```bash
ldapsearch -x -H ldap://<dc_ip> -b "dc=<dc_name>,dc=<dc_name_extension>"
```

##### Example
```bash
ldapsearch -x -H ldap://192.168.159.130 -b "dc=draven,dc=me"
```

##### Result
In this case, the attack failed because anonymous authentication was disabled on the Domain Controller. However, it's always worth attempting as some organizations leave this misconfigured.

See: `Screenshots/enumeration/enum_attacks` folder for detailed results.

---

### 3.2 Kerberos KDC Discovery

Locate Kerberos Key Distribution Centers (KDCs) through SRV record enumeration.

#### Command
```bash
dig @<dc_ip> _kerberos._tcp.<domain_name> SRV
```

#### Results
This reveals:
- Domain Controller hostname
- Kerberos service port (typically 88)
- KDC location

This information is crucial for subsequent attacks such as:
- AS-REP Roasting
- Kerberoasting
- Authentication attempts

See: `/Screenshots/enumeration/DNS_enum`

---

#### 3.2.1 User Enumeration via Kerberos

Now that we've confirmed Kerberos is running on port 88, we can enumerate valid domain users.

##### Step 1: Prepare Username List

Create a text file containing potential usernames to test against the domain.

##### Step 2: User Enumeration with Kerbrute

**Tool:** `kerbrute`

###### Command
```bash
kerbrute userenum -d "<domain_name>" <users_filename>.txt --dc "<dc_ip>" -o <output_file>.txt -vv
```

###### Results
Successfully identified **3 valid users** in the domain.

---

##### Step 3: AS-REP Roasting Attack

Test discovered users for AS-REP Roasting vulnerability. This attack targets user accounts that don't require Kerberos pre-authentication.

**Tool:** `impacket-GetNPUsers`

###### Command
```bash
impacket-GetNPUsers <domain_name>/ -usersfile <valid_users_file> -dc-ip <dc_ip> -no-pass
```

###### What This Does
- Tests each user for pre-authentication requirement
- If vulnerable, retrieves password hashes
- Hashes can be cracked offline using tools like Hashcat or John the Ripper

###### Results
In this case, no users were vulnerable to AS-REP Roasting. The accounts all had pre-authentication enabled, which is the secure configuration.

> **Note:** Results may vary in different environments. Always test thoroughly as misconfigurations are common.

---

## Security Considerations

⚠️ **Warning:** These techniques should only be used in authorized penetration testing engagements or in your own lab environment. Unauthorized access to computer systems is illegal.

---

## Next Steps

If AS-REP Roasting is unsuccessful, consider:
- Password spraying attacks
- SMB enumeration
- Responder/LLMNR poisoning
- Targeting other services identified in the Nmap scan

---

## References

- [Impacket Tools](https://github.com/SecureAuthCorp/impacket)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [LDAP Search Documentation](https://linux.die.net/man/1/ldapsearch)

---

## Lab Environment

**Target:** Domain Controller  
**Tools Used:**
- Nmap
- dig
- ldapsearch
- kerbrute
- impacket-GetNPUsers