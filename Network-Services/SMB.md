
# SMB (Server Message Block) Protocol

Port: 445, 139, 137, 138
## Overview

- **SMB** is a client-server *communication protocol* for sharing access to files, printers, serial ports, and other network resources.
- **Servers** expose file systems and resources (printers, named pipes, APIs) to clients.
- **Clients** connect using:
  - **TCP/IP** (NetBIOS over TCP/IP, per RFC1001 & RFC1002)
  - **NetBEUI**
  - **IPX/SPX**

![SMB](https://github.com/user-attachments/assets/a0cf4470-ece6-4b9c-8392-eea1c021ccc9)


#### Samba
- Provides SMB support for Unix systems.
- Compatible since Windows 95.

#### Solutions: 

1. What does SMB stand for?
```plaintext 
Server Message Block
```

2. What type of protocol is SMB? 
```plaintext
response-request`
```

3. What protocol suite do clients use?
```plaintext
TCP/IP
```

4. What systems does Samba run on?
```plaintext
Unix
```
---

# Enumerating SMB

Gathering information on usernames, passwords, shares, etc.
#### Tools
1. **Nmap** – Basic SMB port scanning.
2. **Enum4Linux** – Comprehensive SMB enumeration.

#### Enum4Linux Usage
```bash
enum4linux [options] <IP>
```

| **Tag** | **Function**                     |
|---------|----------------------------------|
| `-U`    | Get userlist                    |
| `-M`    | Get machine list                |
| `-N`    | Get namelist dump               |
| `-S`    | Get sharelist                   |
| `-P`    | Get password policy info        |
| `-G`    | Get group and member list       |
| `-a`    | Full basic enumeration         |

**Data Collected:**
- Workgroup name
- OS version
- Usernames & passwords
- Open SMB ports
- Machine name
- Available shares
#### Solutions:

1. Conduct an **nmap** scan of your choosing, How many ports are open?
```plaintext
3
```

2. What ports is **SMB** running on? Provide the ports in ascending order.
```plaintext
139,445
```

3. Let's get started with Enum4Linux, conduct a full basic enumeration. For starters, what is the **workgroup** name?
```plaintext
WORKGROUP
```

4. What comes up as the **name** of the machine?
```plaintext
POLOSMB
```

5. What operating system **version** is running?
```plaintext
6.1
```

6. What share sticks out as something we might want to investigate?
```plaintext
profiles
```
---

# Exploiting SMB

Common vulnerabilities include:
- **CVE-2017-7494** (Remote Code Execution)
- **Anonymous SMB Access** (Misconfiguration leading to info leaks)

#### Exploitation Method: 
From enumeration, we typically know:
- SMB share location (e.g., `workgroup: workgroup`)
- Interesting share names (e.g., `profiles`)

#### SMBclient
Connect to an SMB share:
```bash
smbclient //<IP>/<SHARE> -U <USERNAME> -p <PORT>
```
**Example:**
```bash
smbclient //10.10.10.2/secret -U suit -p 445
```

**Useful Commands Inside SMB Shell:**

| Command       | Description                     |
| ------------- | ------------------------------- |
| `help`        | List available commands         |
| `ls`          | List files                      |
| `cd <dir>`    | Change directory                |
| `mget <file>` | Download file                   |
| `more <file>` | View file contents (like `cat`) |

Here's your requested format:

#### Solutions:

1. What would be the correct syntax to access an SMB share called "secret" as user "suit" on a machine with the IP 10.10.10.2 on the default port?
```bash
smbclient //10.10.10.2/secret -U suit -p 445
```

2. Does the share allow anonymous access? Y/N?
```plaintext
Y
```

3. Who can we assume this profile folder belongs to?
```plaintext
John Cactus
```

4. What service has been configured to allow him to work from home?
```plaintext
ssh
```

5. What directory on the share should we look in?
```plaintext
.ssh
```

6. Which of these keys is most useful to us?
```plaintext
id_rsa
```

Download command used:
```smbclient
mget id_rsa download_id_rsa
```

SSH into the target server: 
```bash 
ssh cactus@<target_ip> -i download_id_rsa
```

8. What is the smb.txt flag?
```plaintext
THM{smb_is_fin_eh?}
```

