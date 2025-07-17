# Incident Handling with Splunk

### Executive Summary
Wayne Enterprises experienced a cyberattack resulting in the defacement of its public-facing website (imreallynotbatman.com). The attackers left their trademark and a defacement message. This report details the investigation using Splunk analysis across multiple log sources, following the Cyber Kill Chain framework to reconstruct the attack timeline and identify IOCs.
obsidian://open?vault=Obsidian%20Vault&file=CY%2FImages%2FPasted%20image%2020250618202509.png
### Incident Overview
- **Affected Organization:** Wayne Enterprises
- **Compromised Asset:** Web server hosting imreallynotbatman.com
- **Attack Impact:** Website defacement with attacker's trademark
- **Defacement Evidence:** 
<img width="912" height="511" alt="image" src="https://github.com/user-attachments/assets/53c1260c-d937-4ba1-867d-2d04d68c0969" />



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

<img width="632" height="398" alt="image" src="https://github.com/user-attachments/assets/78c23e04-eff6-4fde-94b1-b7346f1869ea" />


#### Suricata Alert Correlation
**Query:**  
```index=botsv1 sourcetype=Suricata src_ip=40.80.148.42```

**Vulnerability Identification:**  
ShellShock exploit attempt (CVE-2014-6271) detected  
<img width="1262" height="210" alt="image" src="https://github.com/user-attachments/assets/bcb02525-bb6a-4f6b-975b-7bcf25640699" />



#### CMS Identification
**Query:**  
```index=botsv1 sourcetype=stream:http imreallynotbatman.com```

**Finding:**  
Joomla CMS identified through URL patterns  
<img width="1214" height="929" alt="image" src="https://github.com/user-attachments/assets/1e907f31-1ccb-45af-ab41-d379acbe1998" />


#### Attacker Tools
**Web Scanner Identification:**  
Acunetix scanner detected via User-Agent analysis  
<img width="1053" height="267" alt="image" src="https://github.com/user-attachments/assets/7fbda077-1a89-42c1-b675-599fa591de36" />



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
<img width="1209" height="187" alt="image" src="https://github.com/user-attachments/assets/6e563268-2c46-4d95-907c-621dac1d5c9b" />

 

#### Brute-Force Attack on Joomla Admin Portal  
**Targeted URI:** `/joomla/administrator/index.php`  
**Query:**  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data`  

- **Attack Pattern:** Repeated POST requests with `form_data` containing credentials.  
- **Primary Username Targeted:** `admin`  
<img width="1829" height="767" alt="image" src="https://github.com/user-attachments/assets/3c0857ec-85e5-40f0-81c2-48e92ef96306" />

  

#### Credential Extraction via Regex  
**Query:**  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table _time src_ip uri http_user_agent creds`  

- **Results:** 413 total attempts, including **1 successful login** with password `batman` from IP `40.80.148.42`.  
- **Brute-Force IP:** `23.22.63.114` (Python script detected in `http_user_agent`).  
<img width="1834" height="890" alt="image" src="https://github.com/user-attachments/assets/f27f9d8c-e2f0-4754-9430-d07dd94ec878" />


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

<img width="1417" height="800" alt="image" src="https://github.com/user-attachments/assets/57dcfeb2-4911-48b7-953b-c100944c10ef" />

**Verification Query**:  
`index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"`  

<img width="1834" height="890" alt="image" src="https://github.com/user-attachments/assets/779b17ef-c8d5-4cce-8b94-61ae9b904d9b" />



#### Execution Confirmation  
**Query**:  
`index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`  
*(EventCode 1 indicates execution)*  


#### Solutions:  
1. **MD5 Hash of 3791.exe**:  
   - Query: `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`  
   - Result: `AAE3F5A29935E6ABCC2C2754D12A9AF0`  
   <img width="962" height="338" alt="image" src="https://github.com/user-attachments/assets/62d26fe7-b1b0-468d-83d9-837d03ef2adc" />
 

2. **User Who Executed 3791.exe**:  
   - `NT AUTHORITY\IUSR`  

3. **VirusTotal Alternate Name**:  
   - `ab.exe`  
  <img width="1811" height="577" alt="image" src="https://github.com/user-attachments/assets/b8d258e3-9edc-4792-affc-ae94924742ea" />
  

---

# Action on Objectives  

#### Suricata Traffic Analysis  
**Initial Query**:  
`index=botsv1 dest=192.168.250.70 sourcetype=suricata`  
*(No external IPs found communicating with the server)*  

**Outbound Traffic Check**:  
`index=botsv1 src=192.168.250.70 sourcetype=suricata`  
<img width="1012" height="639" alt="image" src="https://github.com/user-attachments/assets/016bee70-51c1-4b0c-acec-c3859efbe025" />


**Suspicious Activity**:  
- Server initiated outbound traffic to external IPs (e.g., `23.22.63.114`).  
- URL field reveals a defacement file: `poisonivy-is-coming-for-you-batman.jpeg`.  

**Query**:  
`index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url`  
<img width="1830" height="459" alt="image" src="https://github.com/user-attachments/assets/06f111e9-ba26-4d85-a2ca-664b1a2bb6f3" />


#### Solutions:  
1. **Defacement Filename**:  
   `poisonivy-is-coming-for-you-batman.jpeg`  

2. **Fortigate SQL Injection Rule**:  
   - Query: `index=botsv1 sourcetype="fortigate_utm" src=40.80.148.42`  
   - Rule: `HTTP.URI.SQL.Injection`  
   <img width="963" height="754" alt="image" src="https://github.com/user-attachments/assets/f8ea2d6d-9ca8-44aa-b495-b4ab39dfd5a6" />
 

---

# Command and Control  

#### Fortigate & HTTP Log Analysis  
**Query**:  
`index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"`  
<img width="1583" height="803" alt="image" src="https://github.com/user-attachments/assets/90f1c40f-d125-49bc-a5d5-f5ba7022958e" />


**Verification via HTTP Logs**:  
`index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70`  
<img width="1419" height="985" alt="image" src="https://github.com/user-attachments/assets/080416bd-9368-4dc1-af25-3bea67b6dc5d" />

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
<img width="1115" height="410" alt="image" src="https://github.com/user-attachments/assets/0e56748a-ec90-4258-8172-df939163cb52" />


#### Threat Actor Infrastructure
- **IP Address:** 23.22.63.114 (hosting attacker-controlled domains)  
<img width="1138" height="399" alt="image" src="https://github.com/user-attachments/assets/01560261-879f-408f-befd-d79b57d61dfc" />


#### VirusTotal Analysis
- **APT Group Association:** Confirmed linkage to Poison Ivy infrastructure  
<img width="1178" height="664" alt="image" src="https://github.com/user-attachments/assets/3fa64611-b23c-422e-a985-e0936f86f87f" />

#### Attacker Attribution
- **Associated Email:** `lillian.rose@po1s0n1vy.com` (via AlienVault OTX)  
<img width="1441" height="801" alt="image" src="https://github.com/user-attachments/assets/c0d09ffd-dfa5-42ff-9059-e127e50ef2b4" />


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
<img width="917" height="457" alt="image" src="https://github.com/user-attachments/assets/23ed30ad-e0b0-4b20-8b9f-d55189784db3" />


#### VirusTotal Confirmation
- **Malware Filename:** `MirandaTateScreensaver.scr.exe`  
<img width="1812" height="315" alt="image" src="https://github.com/user-attachments/assets/0bbe7bb0-7799-41df-a579-9d4f5e3b97ec" />


#### Hybrid-Analysis Insights
- **Key Indicators:**
  - C2 communication patterns
  - MITRE ATT&CK techniques mapped
  - Suspicious DLL imports  
<img width="1151" height="777" alt="image" src="https://github.com/user-attachments/assets/8526c547-a6b9-4c46-9b20-c736f2566b1c" />


#### Solutions
1. **Malware hash value:**  
   > `c99131e0169171935c5ac32615ed6261`

2. **Malware filename:**  
   > `MirandaTateScreensaver.scr.exe`

