
Metasploit is the most widely used exploitation framework. It is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation.

Useful in : **Pentesting + exploit dev**

- **Metasploit Pro:** GUI
- **Metasploit Framework:** Open-source CLI
    
- **msfconsole:** CLI
- **Modules:** Supporting modules — scanners, payloads, exploits
- **Tools:** Vulnerability assessment, e.g., `msfvenom`, `pattern_create`, and `pattern_offset`
    
--- 
## Main components of Metasploit

- **Vulnerability** → Weakness in a system (bug/flaw). (e.g., unpatched software)
- **Exploit** → Code that **uses** the vulnerability to attack. (e.g., code that crashes it)
- **Payload** → Malicious code **delivered** by the exploit (e.g., gives shell access, installs a backdoor)
    

>**TL;DR:**  
  **Exploit** abuses a **vulnerability** to deliver a **payload**.

- `auxiliary`: Any supporting module such as scanners, crawlers, and fuzzers.
    
- `encoders`: Scramble exploits/payloads to dodge basic antivirus scans. But modern AVs use behavior analysis, so encoders often fail.  
    _(Think: changing a burglar’s outfit to avoid CCTV — works on old cameras, but not AI-powered ones.)_
    
- `evasion`: Unlike encoders, evasion modules attempt to evade antivirus detection directly, with varying success.
    
- `exploits`: Organized by target system.
    
- `NOPs`: “No Operation” instructions (e.g., `0x90` in Intel x86) used as padding or buffers for consistent payload sizes.
    
- `payloads`: Executed on the target. Exploits use vulnerabilities to deliver these (e.g., reverse shell, `calc.exe`).
    
    - **Adapters** → Bridge incompatible components
    - **Singles** → Self-contained, all-in-one payloads
    - **Stagers** → Small initial code to fetch bigger payloads
    - **Stages** → Modular payloads for flexibility
    
    Examples:
    - `generic/shell_reverse_tcp` → single payload
    - `windows/x64/shell/reverse_tcp` → staged payload
        
- `post`: Post modules are used during the post-exploitation phase.
    

More info can be found in

```bash
/opt/metasploit-framework/embedded/framework/modules
```

## Msfconsole

Common commands:

```bash
ls, clear, help <command>
```

- Autocomplete works with `TAB`.
    
Example: EternalBlue exploit for Windows (MS17-010)

```msf6
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

> The prompt changes, but you're not in a directory just a **new context** for the selected module.

```msf6
msf6 exploit(windows/smb/ms17_010_eternalblue) > ls 
[*] exec: ls
```

To list available options for the module:

```bash
show options
```

This exploit requires:

- `RHOSTS` → Target IP
- `RPORT` → Target port
    

![[Pasted image 20250519130213.png]]

Some **post-exploitation modules** only require a session ID.

![[Pasted image 20250519130232.png]]

#### Other `show` commands:

```bash
show payloads
show exploits
show options
show auxiliary
```

Navigation:

- `back`: Exit module context.
- `info`: Get details of the current module.
- `search <keyword>`: Find modules (indexed).
- `use 0`: Use module with index 0 (from search results).
- Search with keywords: 
```bash
msf6 > search type:auxiliary telnet 
```

#### Module ranking is shown like below:

![[Pasted image 20250519193503.png]]

---

##  Working With Modules

You’re in the `msf6` prompt. If a shell is obtained, it may transition to a Meterpreter prompt (`meterpreter >`).

#### Setting parameters: 

```bash
set <parameter> <value>
```

#### Common Parameters

|Parameter|Meaning|
|---|---|
|`RHOSTS`|Remote host IP address (target)|
|`RPORT`|Remote port (target service port)|
|`LHOST`|Local host (attacker’s IP)|
|`LPORT`|Local port for reverse shell|
|`PAYLOAD`|Chosen payload|
|`SESSION`|Session ID used for post modules|

### Useful Commands

- `setg`, `unsetg`: Set/unset global values across all modules.
- `check`: Check if the target is vulnerable (non-intrusive).
- `exploit -z`: Run in background without creating session.
- `run`: Start exploit/module.
- `background` or `Ctrl+Z`: Move session to background.
- `sessions`: View active sessions.
- `sessions -i <id>`: Interact with a specific session.
