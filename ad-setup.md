# AD-Lab

Active Directory homelab built for red-team practice, focusing on AD enumeration, privilege escalation, credential attacks, and post-exploitation techniques.

This project is a homelab environment designed for practicing offensive security techniques against a Windows Active Directory domain. The setup includes:

- A **domain controller**
- **Domain-joined Windows clients**
- An **attacker machine**

The goal is to simulate real-world internal network penetration testing.

The lab focuses on **Active Directory enumeration, privilege escalation paths, credential extraction, lateral movement, and post-exploitation techniques.** All attacks are performed in an isolated environment strictly for educational and ethical research purposes.

---

## 🔧 Key Techniques & Topics

- **Recon & Enumeration**
  - LDAP, SMB, BloodHound
- **Credential Harvesting**
  - LSASS dump, Mimikatz, DPAPI
- **Kerberoasting & AS-REP Roasting**
- **Pass-the-Hash / Pass-the-Ticket**
- **Golden & Silver Tickets**
- **Lateral Movement**
  - WinRM, RDP, SMB
- **ADCS Escalation**

---

## ⚠ Disclaimer

This project is strictly for educational purposes in a controlled lab environment.  
**Do not apply these techniques on networks you do not own or have explicit authorization to test.**



# Active Directory Lab Setup (Red Team Focus)

This guide walks through setting up a vulnerable Active Directory lab for offensive security and red-team practice using PowerShell.

---

## **🔧 Prerequisites**

You will need:

- Windows Server (2019 or 2022)
- Windows 10 Enterprise
- Virtualization software (VMware Workstation / VirtualBox)

Create two virtual machines:

| Role | OS | Description |
|------|------|-------------|
| **Domain Controller** | Windows Server | Hosts AD + DNS |
| **Client Machine** | Windows 10 | Domain-joined workstation |

---

## **1️⃣ Install Active Directory (PowerShell)**

Run the following commands on **Windows Server**:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSForest `
 -CreateDnsDelegation:$false `
 -DatabasePath "C:\Windows\NTDS" `
 -DomainMode "7" `
 -DomainName "cs.org" `
 -DomainNetbiosName "cs" `
 -ForestMode "7" `
 -InstallDns:$true `
 -LogPath "C:\Windows\NTDS" `
 -SysvolPath "C:\Windows\SYSVOL" `
 -NoRebootOnCompletion:$false `
 -Force:$true
             
## **2️⃣ Deploy a Vulnerable AD Structure**

 If AD is already installed, download and execute the script to generate a vulnerable domain for red-team practice:

(New-Object Net.WebClient).DownloadFile(
 "https://raw.githubusercontent.com/safebuffer/vulnerable-AD/refs/heads/master/vulnad.ps1",
 "C:\vulnad.ps1"
)

Import-Module C:\vulnad.ps1
Invoke-VulnAD

	
  ⚠ **Disclaimer:**
 > Make sure PowerShell execution policy allows running scripts.
 > Example: Set-ExecutionPolicy Bypass -Scope Process

## **3️⃣ Configure Static IPs**
	
Static IPs are required to ensure domain stability and proper DNS functionality.
Set static IP on Windows Server
Set static IP on Windows 10
Confirm both are in the same IP range

⚠ **Disclaimer:**  
   > Both machines must use the same network mode (NAT / Host-Only / Bridged — not mixed).
     Bridged is not recommended for security.

📸 Screenshots available in /screenshots.

## **4️⃣ Join Windows 10 to the Domain**

Once networking is configured:
1. Open System Settings → Rename this PC (Advanced)
2. Join domain: draven.me
3. Reboot when prompted.

Example:
The client machine (dravenvictime) was added to the draven.me domain.

To verify connectivity:
ping <domain-controller-ip>
📸 Screenshots available in /screenshots.
  