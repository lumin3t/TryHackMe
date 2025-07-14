# OWASP Top 10 Vulnerabilities Analysis

## 1. Broken Access Control

### Key Risks:
- Unauthorized viewing of sensitive information
- Access to restricted functionality

### Example Case:
A 2019 YouTube vulnerability allowed attackers to reconstruct private videos by extracting individual frames ([Reference](https://bugs.xdavidhu.me/google/2021/01/11/stealing-your-private-videos-one-frame-at-a-time/)).

### IDOR Vulnerability
**Insecure Direct Object Reference** occurs when applications expose internal object references without proper authorization checks.

**Example:**
```http
http://10.10.162.249/note.php?note_id=0
```
*Flag found:* `flag{fivefourthree}`

---

## 2. Cryptographic Failures

### Common Issues:
- Lack of transport layer encryption
- Poor storage encryption practices
- MITM vulnerabilities

### Demonstration:
SQLite database exposure with plaintext credentials:
```sql
SELECT * FROM users;
```
![[Pasted image 20250627223213.png]]

---

## 3. Injection Vulnerabilities

### Types:
- **SQL Injection:** Unsanitized user input in database queries
- **Command Injection:** User input passed to system commands

### Case Study:
Vulnerable PHP code:
```php
passthru("perl /usr/bin/cowsay -f $cow $mooing");
```

**Exploit:**
```http
http://example.com/cowsay.php?mooing=$(ls)&cow=default
```
![[9f657b909062ac82af12548b4f346aec.png]]

---

## 4. Insecure Design

### Architectural Flaws:
- Fundamental security weaknesses in application design
- Example: Instagram's OTP brute-force vulnerability (250 attempts/IP limit bypassed with IP rotation)

### Demonstration:
```text
Password hint: "His favorite color was green"
```
![[Pasted image 20250627230649.png]]

---

## 5. Security Misconfiguration

### Common Issues:
- Default credentials
- Excessive permissions
- Verbose error messages
- Missing security headers

### Example:
Exposed database file:
```python
import os; print(os.popen("cat app.py").read())
```
![[Pasted image 20250630175116.png]]

---

## 6. Vulnerable Components

### Risks:
- Unpatched software vulnerabilities
- Example: WordPress 4.6 RCE (CVE-2016-10033)

### Exploitation:
```bash
wpscan --url http://target.com --enumerate vp
```
![[Pasted image 20250701175701.png]]

---

## 7. Authentication Failures

### Common Weaknesses:
- Weak password policies
- Lack of brute-force protection
- Insecure session management

### Demonstration:
Weak session cookie:
```http
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
![[Pasted image 20250701180148.png]]

---

## 8. Integrity Failures

### Key Concepts:
- Data verification via hashes
- JWT security considerations

### Case Study:
JWT "none" algorithm vulnerability:
```json
{"alg":"none","typ":"JWT"}
```
![[f5d1b4ef49ff4eef52e7617631225e8a.png]]

---

## 9. Logging & Monitoring Failures

### Critical Log Data:
- Timestamps
- User activities
- IP addresses
- API endpoints

### Attack Indicators:
- Brute-force patterns
- Anomalous IP locations
- Automated tool signatures

---

## 10. SSRF Vulnerabilities

### Exploitation:
```http
https://vulnerable.com/api?url=http://internal-server
```

### Impact:
- Internal network reconnaissance
- Service enumeration

### Detection:
```text
GET /:8087/public-docs/123.pdf HTTP/1.1
Host: 10.10.10.11
```
![[Pasted image 20250701181012.png]]
