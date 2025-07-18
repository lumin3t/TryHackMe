# Incident Response Report: Wayne Enterprises Web Defacement Attack

## Executive Summary
On June 18, 2025, Wayne Enterprises' public-facing website (imreallynotbatman.com) was compromised through a coordinated cyberattack resulting in website defacement. Forensic analysis utilizing Splunk revealed attacker tactics aligned with the Poison Ivy threat group, leveraging Joomla vulnerabilities and brute-force techniques. This report documents the attack lifecycle through the Cyber Kill Chain framework with corresponding Indicators of Compromise (IOCs).

## Incident Overview

### Key Incident Details
- **Affected Organization:** Wayne Enterprises
- **Compromised Asset:** Web server (imreallynotbatman.com)
- **Attack Vector:** Joomla CMS exploitation (CVE-2014-6271)
- **Impact:** Website defacement with threat actor signature
- **Threat Actor Attribution:** Poison Ivy APT group

### Defacement Evidence
<img width="912" height="511" alt="Defaced Website" src="https://github.com/user-attachments/assets/53c1260c-d937-4ba1-867d-2d04d68c0969" />

## Investigation Methodology

### Data Sources Utilized
| Log Source              | Analysis Purpose                          |
|-------------------------|-------------------------------------------|
| XmlWinEventLog (Sysmon) | Process execution tracking                |
| Suricata                | Network intrusion detection               |
| fortigate_utm           | Firewall traffic analysis                 |
| stream:http             | Web request forensics                     |
| wineventlog             | Windows system activity                   |

### Cyber Kill Chain Alignment
1. **Reconnaissance:** Attacker scanning and vulnerability identification
2. **Weaponization:** Malware payload preparation
3. **Delivery:** Exploit execution and initial access
4. **Exploitation:** Joomla admin portal compromise
5. **Installation:** Persistent backdoor deployment
6. **Command & Control:** C2 channel establishment
7. **Actions on Objectives:** Website defacement

---

## Phase 1: Reconnaissance

### Attacker Scanning Activity
**Primary Attacker IP:** 40.80.148.42  
**Detection Query:**  
```index=botsv1 imreallynotbatman.com sourcetype=stream:http```

<img width="632" height="398" alt="Scanning Activity" src="https://github.com/user-attachments/assets/78c23e04-eff6-4fde-94b1-b7346f1869ea" />

### Vulnerability Identification
**Critical Finding:**  
- ShellShock exploit attempt (CVE-2014-6271)  
- Joomla CMS fingerprinting  

<img width="1262" height="210" alt="Suricata Alert" src="https://github.com/user-attachments/assets/bcb02525-bb6a-4f6b-975b-7bcf25640699" />

### Attacker Tooling
**Web Scanner:** Acunetix  
**Detection Method:** User-Agent analysis  

<img width="1053" height="267" alt="Scanner Identification" src="https://github.com/user-attachments/assets/7fbda077-1a89-42c1-b675-599fa591de36" />

### Key Indicators
| Indicator Type       | Value               |
|----------------------|---------------------|
| Attacker IP          | 40.80.148.42        |
| Web Scanner          | Acunetix            |
| Exploited CVE        | CVE-2014-6271       |
| Target CMS           | Joomla              |

---

## Phase 2: Exploitation

### Brute-Force Attack Pattern
**Target:** Joomla Administrator Portal (/joomla/administrator/index.php)  
**Attack Source IP:** 23.22.63.114  
**Successful Credentials:** admin:batman  

<img width="1829" height="767" alt="Brute-Force Attempts" src="https://github.com/user-attachments/assets/3c0857ec-85e5-40f0-81c2-48e92ef96306" />

### Compromise Statistics
- Total Attempts: 413  
- Unique Passwords Tested: 412  
- Successful Login IP: 40.80.148.42  

---

## Phase 3: Installation

### Malicious Payload Delivery
**Files Identified:**  
- 3791.exe (MD5: AAE3F5A29935E6ABCC2C2754D12A9AF0)  
- agent.php  

<img width="1417" height="800" alt="Payload Upload" src="https://github.com/user-attachments/assets/57dcfeb2-4911-48b7-953b-c100944c10ef" />

### Execution Confirmation
**Process Context:**  
- User: NT AUTHORITY\IUSR  
- VT Detection: ab.exe (Poison Ivy variant)  

<img width="962" height="338" alt="Process Execution" src="https://github.com/user-attachments/assets/62d26fe7-b1b0-468d-83d9-837d03ef2adc" />

---

## Phase 4: Actions on Objectives

### Defacement Artifact
**Filename:** poisonivy-is-coming-for-you-batman.jpeg  
**C2 Domain:** prankglassinebracket.jumpingcrab.com  

<img width="1830" height="459" alt="Defacement File" src="https://github.com/user-attachments/assets/06f111e9-ba26-4d85-a2ca-664b1a2bb6f3" />

---

## Threat Actor Attribution

### Infrastructure Analysis
**Primary Domain:** www.po1s0n1vy.com  
**Associated IP:** 23.22.63.114  

<img width="1115" height="410" alt="Attacker Infrastructure" src="https://github.com/user-attachments/assets/0e56748a-ec90-4258-8172-df939163cb52" />

### Malware Characteristics
**Filename:** MirandaTateScreensaver.scr.exe  
**Hash:** c99131e0169171935c5ac32615ed6261  

<img width="1812" height="315" alt="VirusTotal Analysis" src="https://github.com/user-attachments/assets/0bbe7bb0-7799-41df-a579-9d4f5e3b97ec" />

---

## Conclusion
This investigation confirmed a multi-phase attack by the Poison Ivy threat group, exploiting Joomla vulnerabilities to establish persistent access. The attacker's infrastructure and TTPs align with known APT campaigns targeting enterprise web assets.

### Recommended Actions
1. Immediate password rotation for all administrative accounts
2. Patching of CVE-2014-6271 vulnerability
3. Blocking of identified IOCs at network perimeter
4. Enhanced monitoring for C2 communication patterns

**Incident Response Team**  - @lumin3t
