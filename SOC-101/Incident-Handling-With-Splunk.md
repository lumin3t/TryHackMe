# Incident Handling with Splunk

### Executive Summary
Wayne Enterprises experienced a cyberattack resulting in the defacement of its public-facing website (imreallynotbatman.com). The attackers left their trademark and a defacement message. This report details the investigation using Splunk analysis across multiple log sources, following the Cyber Kill Chain framework to reconstruct the attack timeline and identify IOCs.

### Incident Overview
- **Affected Organization:** Wayne Enterprises
- **Compromised Asset:** Web server hosting imreallynotbatman.com
- **Attack Impact:** Website defacement with attacker's trademark
- **Defacement Evidence:** 
![[dcc528c218e8dda78504f55f58188575.png]]

### Methodology
#### Data Sources
| Log Source              | Purpose                                    |
| ----------------------- | ------------------------------------------ |
| XmlWinEventLog (Sysmon) | Process creation, network connections      |
| Suricata                | IDS alerts and network intrusion detection |
| fortigate_utm           | Firewall traffic and security events       |
| stream:http             | Web traffic analysis                       |
| wineventlog             | Windows system activity                    |

### Cyber Kill Chain Framework
1. Reconnaissance
2. Weaponization  
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives

---

# Reconnaissance Phase

#### Initial Scanning Detection
**Query:**  
```index=botsv1 imreallynotbatman.com sourcetype=stream:http```

**Key Finding:**  
IP `40.80.148.42` identified as primary attacker source through HTTP traffic analysis.

![[Pasted image 20250618202509.png]]

#### Suricata Alert Correlation
**Query:**  
```index=botsv1 sourcetype=Suricata src_ip=40.80.148.42```

**Vulnerability Identification:**  
ShellShock exploit attempt (CVE-2014-6271) detected  
![[Screenshot 2025-06-18 203713.png]]

#### CMS Identification
**Query:**  
```index=botsv1 sourcetype=stream:http imreallynotbatman.com```

**Finding:**  
Joomla CMS identified through URL patterns  
![[Screenshot 2025-06-18 203453.png]]

#### Attacker Tools
**Web Scanner Identification:**  
Acunetix scanner detected via User-Agent analysis  
![[Pasted image 20250618210822.png]]

#### Infrastructure Details
**Web Server IP:**  
192.158.250.70 (from destination IP analysis)

#### Key Findings
1. **Initial Access:**  
   - Attackers used Acunetix scanner from 40.80.148.42
   - Targeted Joomla CMS vulnerabilities (CVE-2014-6271)

2. **Vulnerabilities Exploited:**  
   - ShellShock (CVE-2014-6271)
   - Joomla administrative interface weaknesses

3. **Attack Infrastructure:**  
   - Primary attacker IP: 40.80.148.42
   - Compromised server: 192.158.250.70


| Indicator   | Type     | Value         |
| ----------- | -------- | ------------- |
| Attacker IP | IPv4     | 40.80.148.42  |
| Web Scanner | Tool     | Acunetix      |
| Exploit     | CVE      | CVE-2014-6271 |
| CMS         | Software | Joomla        |


---

# Exploitation Phase Analysis  

This phase examines how the attacker exploited vulnerabilities to gain unauthorized access to the `imreallynotbatman.com` web server, focusing on brute-force attacks against the Joomla administrator portal.  

#### Initial HTTP Traffic Assessment  
**Query:**  
`index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests`  

- **Key Finding:** IP `23.22.63.114` generated a high volume of POST requests, suggesting scanning or brute-forcing.  
![[Pasted image 20250618212202.png]]  

#### Brute-Force Attack on Joomla Admin Portal  
**Targeted URI:** `/joomla/administrator/index.php`  
**Query:**  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data`  

- **Attack Pattern:** Repeated POST requests with `form_data` containing credentials.  
- **Primary Username Targeted:** `admin`  
![[9c47791d96dbadf8ab0d6a0adf1a9508.png]]  

#### Credential Extraction via Regex  
**Query:**  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table _time src_ip uri http_user_agent creds`  

- **Results:** 413 total attempts, including **1 successful login** with password `batman` from IP `40.80.148.42`.  
- **Brute-Force IP:** `23.22.63.114` (Python script detected in `http_user_agent`).  
![[Pasted image 20250618212908.png]]  

#### Solutions  
1. **Brute-Forced URI:**  
   > `/joomla/administrator/index.php`  

2. **Targeted Username:**  
   > `admin`  

3. **Valid Password:**  
   > `batman`  

4. **Unique Passwords Attempted:**  
   > `412` (excluding the correct password)  

5. **Brute-Force Attacker IP:**  
   > `23.22.63.114`  

6. **IP Used for Successful Login:**  
   > `40.80.148.42`  


---

# Installation Phase  

This phase identifies malicious payloads uploaded and installed on the server from attacker IPs.  

#### Detection of Malicious Executable  
**Search Query**:  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe`  

The field `part_filename{}` reveals two files:  
- `3791.exe` (executable)  
- `agent.php` (PHP script)  

![[Pasted image 20250714121632.png]]  

**Verification Query**:  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"`  

![[Pasted image 20250714121645.png]]  

#### Execution Confirmation  
**Query**:  
`index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`  
*(EventCode 1 indicates execution)*  


#### Solutions:  
1. **MD5 Hash of 3791.exe**:  
   - Query: `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`  
   - Result: `AAE3F5A29935E6ABCC2C2754D12A9AF0`  
   ![[Screenshot 2025-06-19 101447.png]]  

2. **User Who Executed 3791.exe**:  
   - `NT AUTHORITY\IUSR`  

3. **VirusTotal Alternate Name**:  
   - `ab.exe`  
   ![[Screenshot 2025-06-19 101527.png]]  

---

# Action on Objectives  

#### Suricata Traffic Analysis  
**Initial Query**:  
`index=botsv1 dest=192.168.250.70 sourcetype=suricata`  
*(No external IPs found communicating with the server)*  

**Outbound Traffic Check**:  
`index=botsv1 src=192.168.250.70 sourcetype=suricata`  
![[Pasted image 20250714123140.png]]  

**Suspicious Activity**:  
- Server initiated outbound traffic to external IPs (e.g., `23.22.63.114`).  
- URL field reveals a defacement file: `poisonivy-is-coming-for-you-batman.jpeg`.  

**Query**:  
`index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url`  
![[Screenshot 2025-06-19 102122.png]]  

#### Solutions:  
1. **Defacement Filename**:  
   `poisonivy-is-coming-for-you-batman.jpeg`  

2. **Fortigate SQL Injection Rule**:  
   - Query: `index=botsv1 sourcetype="fortigate_utm" src=40.80.148.42`  
   - Rule: `HTTP.URI.SQL.Injection`  
   ![[Screenshot 2025-06-19 102509.png]]  

---

# Command and Control  

#### Fortigate & HTTP Log Analysis  
**Query**:  
`index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"`  
![[Pasted image 20250714124120.png]]  

**Verification via HTTP Logs**:  
`index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70`  
![[Pasted image 20250714124206.png]]  

#### Solution:  
1. **Malicious FQDN**:  
   `prankglassinebracket.jumpingcrab.com`  

---

# Weaponization Phase Analysis

The weaponization phase reveals how attackers prepared malicious infrastructure and tools targeting Wayne Enterprises.

### OSINT Findings

#### Domain Intelligence (Robtex)
- **Primary Attacker Domain:** `www.po1s0n1vy.com`
- **Suspicious Subdomains:** Multiple domains mimicking Wayne Enterprises infrastructure  
![[Pasted image 20250714125737.png]]

#### Threat Actor Infrastructure
- **IP Address:** 23.22.63.114 (hosting attacker-controlled domains)  
![[Pasted image 20250714125813.png]]

#### VirusTotal Analysis
- **APT Group Association:** Confirmed linkage to Poison Ivy infrastructure  
![[Pasted image 20250714125929.png]]

#### Attacker Attribution
- **Associated Email:** `lillian.rose@po1s0n1vy.com` (via AlienVault OTX)  
![[Pasted image 20250714130033.png]]


#### Solutions
1. **IP address tied to pre-staged attack domains:**  
   > `23.22.63.114`

2. **APT group contact email:**  
   > `lillian.rose@po1s0n1vy.com`

---

# Delivery Phase 

Attackers distributed malware through compromised infrastructure, leveraging multiple threat intelligence platforms for validation.

### Malware Analysis

#### ThreatMiner Findings
- **Malware Hash:** `c99131e0169171935c5ac32615ed6261`  
![[Pasted image 20250714130320.png]]

#### VirusTotal Confirmation
- **Malware Filename:** `MirandaTateScreensaver.scr.exe`  
![[Pasted image 20250714130520.png]]

#### Hybrid-Analysis Insights
- **Key Indicators:**
  - C2 communication patterns
  - MITRE ATT&CK techniques mapped
  - Suspicious DLL imports  
![[Pasted image 20250714130622.png]]

#### Solutions
1. **Malware hash value:**  
   > `c99131e0169171935c5ac32615ed6261`

2. **Malware filename:**  
   > `MirandaTateScreensaver.scr.exe`

