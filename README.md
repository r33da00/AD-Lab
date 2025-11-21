# AD-Lab

> A comprehensive Active Directory homelab environment designed for red team practice, focusing on AD enumeration, privilege escalation, credential attacks, and post-exploitation techniques.

## 📋 Overview

This project provides a controlled, isolated Active Directory environment for practicing offensive security techniques. The lab simulates real-world internal network penetration testing scenarios and includes:

- **Domain Controller** – Windows Server hosting AD DS and DNS services
- **Domain-Joined Clients** – Windows workstations for lateral movement practice
- **Attacker Machine** – Dedicated system for red team operations

The environment is specifically designed for hands-on experience with Active Directory exploitation, credential harvesting, Kerberos attacks, and advanced post-exploitation techniques.

---

## 🔧 Prerequisites

### Software Requirements
- **Hypervisor**: VMware Workstation Pro/Player or VirtualBox
- **Windows Server 2019/2022** (evaluation version acceptable)
- **Windows 10/11 Enterprise** (evaluation version acceptable)

### Network Configuration
All virtual machines must be configured on an **isolated network** (Host-Only or NAT mode) to prevent accidental exposure.

---

## 🚀 Installation Guide

### Step 1: Prepare Virtual Machines

Create the following virtual machines with recommended specifications:

| **Role** | **OS** | **RAM** | **vCPU** | **Disk** |
|----------|--------|---------|----------|----------|
| Domain Controller | Windows Server 2019/2022 | 4GB | 2 | 60GB |
| Client Workstation | Windows 10/11 Enterprise | 4GB | 2 | 60GB |
| Attacker Machine | Kali Linux (optional) | 4GB | 2 | 40GB |

### Step 2: Install Active Directory Domain Services

Execute the following commands on **Windows Server** in an elevated PowerShell session:

```powershell
# Install AD Domain Services role with management tools
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Import deployment module
Import-Module ADDSDeployment

# Promote server to Domain Controller
Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "7" `
    -DomainName "change.me" `
    -DomainNetbiosName "change" `
    -ForestMode "7" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

**Note**: The server will automatically reboot after promotion completes.

### Step 3: Deploy Vulnerable AD Configuration

After AD installation, deploy the vulnerable domain structure for red team practice:

```powershell
# Download vulnerable AD deployment script
(New-Object Net.WebClient).DownloadFile(
    "https://raw.githubusercontent.com/safebuffer/vulnerable-AD/refs/heads/master/vulnad.ps1",
    "C:\vulnad.ps1"
)

# Set execution policy (current session only)
Set-ExecutionPolicy Bypass -Scope Process -Force

# Import and execute vulnerable AD script
Import-Module C:\vulnad.ps1
Invoke-VulnAD
```

**⚠️ Security Warning**: This script intentionally introduces security vulnerabilities. Never deploy this configuration in production environments.

### Step 4: Configure Network Settings

#### Domain Controller Configuration

```powershell
# Configure static IP on Domain Controller
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress <you-ip> -PrefixLength 24 -DefaultGateway <defaultgateway-ip>
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
```

#### Client Workstation Configuration

```powershell
# Configure static IP on Client
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress <you-ip> -PrefixLength 24 -DefaultGateway <defaultgateway-ip>
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses <you-ip>
```

**Network Requirements**:
- All VMs must use the same subnet (e.g., 192.168.100.0/24)
- Use **Host-Only** or **Internal Network** mode in your hypervisor
- Avoid **Bridged** mode to prevent exposure to production networks

### Step 5: Join Client to Domain

On the **Windows Client** machine:

1. Open **System Properties** (Windows + Pause/Break)
2. Click **Change settings** → **Change**
3. Select **Domain** and enter: `<you-domain>`
4. Provide Domain Admin credentials when prompted
5. Restart the machine to complete domain join

**Test Before Joining Domain**:
```powershell
# Verify connectivity via ping
ping <domaincontroller-ip>
nslookup yourdomainname.local
```
# If ping works + DNS resolves → you're ready.
---

## 📸 Documentation

Screenshots and detailed configuration examples are available in the `/screenshots` directory, including:
- Domain controller installation steps
- Network configuration examples
- Domain join verification
- Attack's commands and results

---

## ⚠️ Legal Disclaimer

**This project is strictly for educational and authorized security research purposes only.**

- Only use these techniques in isolated lab environments you own and control
- Never apply these methods to networks without explicit written authorization
- Unauthorized access to computer systems is illegal under laws including the Computer Fraud and Abuse Act (CFAA)
- The authors assume no liability for misuse of this information

By using this lab, you agree to use it responsibly and ethically.

---
