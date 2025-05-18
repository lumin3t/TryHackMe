## TCP Scans
#### 1. TCP Connect Scan (`-sT`)
- **Command**:  
  ```bash
  nmap -sT <target>
  ```
![wireshark](https://github.com/user-attachments/assets/a801621e-b515-49d0-8283-3129bd8fe078)

- **Behavior**:  
  - Completes the full TCP 3-way handshake (`SYN → SYN/ACK → ACK`).  
![syn syn/ack ack](https://github.com/user-attachments/assets/f9b67e67-cf40-45d2-937d-d3e4028d9e54)

  - **Open Port**: Responds with `SYN/ACK`.  
  - **Closed Port**: Responds with `RST`.  
  ![rst](https://github.com/user-attachments/assets/292bb357-fac7-47f9-a295-b5169b2b5ef7)

  - **Filtered Port**: No response (firewall drops packets).  

#### 2. TCP SYN (Stealth) Scan (`-sS`)
- **Command (requires root)**:  
  ```bash
  sudo nmap -sS <target>
  ```
- **Behavior**:  
  - Half-open scan (sends `SYN`, expects `SYN/ACK` for open ports).  
  - **Open Port**: `SYN → SYN/ACK` → Nmap sends `RST` instead of `ACK`.  
  - **Closed Port**: `SYN → RST`.  
  - **Filtered Port**: No response (firewall drops packets).  
- **Advantages**:  
  - Stealthier (doesn’t complete the handshake).  
  - Bypasses older IDS systems that only monitor full connection. (waits for 3 way handshake)
- **Note**: Requires root privileges (or `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities).  

#### Firewall Evasion with `iptables`
- If a firewall spoofs closed ports (sends `RST` for filtered ports):  
  ```bash
  iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
  ```

---

## UDP Scan (`-sU`)
- **Command**:  
  ```bash
  nmap -sU --top-ports 20 <target>
  ```
- **Behavior**:  
  - **Open Port**: No response (or service-specific reply).  
  - **Closed Port**: ICMP "Port Unreachable" error.  
  - **Filtered Port**: No response.  
- **Note**: Slower than TCP scans (UDP is connectionless).  

---

## Stealthy TCP Scans (Firewall Evasion)
#### 1. NULL Scan (`-sN`)
- **Command**:  
  ```bash
  nmap -sN <target>
  ```
- **Behavior**:  
  - Sends a packet with **no TCP flags**.  
  - **Closed Port**: Responds with `RST`.  
  - **Open/Filtered Port**: No response.  

#### 2. FIN Scan (`-sF`)
- **Command**:  
  ```bash
  nmap -sF <target>
  ```
- **Behavior**:  
  - Sends a packet with **only the `FIN` flag** set.  
  - **Closed Port**: Responds with `RST`.  
  - **Open/Filtered Port**: No response.  

#### 3. Xmas Scan (`-sX`)
- **Command**:  
  ```bash
  nmap -sX <target>
  ```
- **Behavior**:  
  - Sends a packet with **`FIN`, `PSH`, `URG` flags** (like a "blinking Christmas tree").  
  - **Closed Port**: Responds with `RST`.  
  - **Open/Filtered Port**: No response.  

**Notes on Stealth Scans** 
- **Windows/Cisco Devices**: Often respond with `RST` to malformed packets (regardless of port state).  
- **Firewall Evasion**: Useful when firewalls drop `SYN` packets.  

---

## Ping Sweep (`-sn`)
- **Command**:  
  ```bash
  nmap -sn 192.168.0.1-254  
  nmap -sn 192.168.0.0/24
  ```
- **Behavior**:  
  - Discovers live hosts using **ARP (LAN) / ICMP (WAN)**.  
  - Does **not** scan ports.  

---

## Nmap Scripting Engine (NSE)

Written in LUA

- **View Script Help**:  
  ```bash
  nmap --script-help <script-name>
  ```
- **Search Scripts**:  
  ```bash
  grep "ftp" /usr/share/nmap/scripts/script.db
  ls -l /usr/share/nmap/scripts/*ftp*
  ```
- **Install New Scripts**:  
  ```bash
  sudo wget -O /usr/share/nmap/scripts/<script-name>.nse https://svn.nmap.org/nmap/scripts/<script-name>.nse
  nmap --script-updatedb
  ```

---

## Firewall Evasion Techniques

| **Option**               | **Description** |
|--------------------------|----------------|
| `-Pn`                   | Skip host discovery (assume host is up). |
| `-f`                    | Fragment packets (smaller MTU). |
| `--mtu <number>`        | Custom MTU (must be multiple of 8). |
| `--scan-delay <time>ms` | Adds delay between probes. |
| `--badsum`              | Sends invalid checksums (tricks firewalls). |
| `--data-length <number>`| Appends random data to packets. |

---

## Service Detection (`-sV`)
- **Command**:  
  ```bash
  nmap -sV <target>
  ```
- **Behavior**:  
  - Probes open ports to detect running services/versions.  

---

## Summary of Common Scan Types

| **Scan Type** | **Command**     | **Use Case**                         |
| ------------- | --------------- | ------------------------------------ |
| TCP Connect   | `nmap -sT`      | Non-root scan.                       |
| TCP SYN       | `sudo nmap -sS` | Stealthy scan (default for root).    |
| UDP Scan      | `nmap -sU`      | Slow but effective for UDP services. |
| NULL/FIN/Xmas | `nmap -sN/F/X`  | Firewall evasion.                    |
| Ping Sweep    | `nmap -sn`      | Host discovery.                      |
