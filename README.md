# Cargo Hold

<p align="center">
  <img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/ff651f44-4fa3-473e-bfeb-9ead7f90c311" />
</p>

## Incident Brief
**INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社**

**SITUATION:** After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.

**COMPROMISED SYSTEMS:** [REDACTED - Investigation Required]

**EVIDENCE AVAILABLE:** Microsoft Defender for Endpoint logs <br>
<br>

The full investigation report can be read [here]()

## Tech Stack
<img width="50" height="50" alt="azure" src="https://github.com/user-attachments/assets/fd2866b6-d2fa-4e61-bf55-0b20d63fca5e" />
<img width="50" height="50" alt="icons8-windows-defender-48" src="https://github.com/user-attachments/assets/41507be1-eadc-440c-b577-ccbf835e91e3" />
<img width="50" height="50" alt="windows logo" src="https://github.com/user-attachments/assets/5b714048-8f2e-4753-b68a-7aa699b5ef38" />
<img width="50" height="50" alt="KQL" src="https://github.com/user-attachments/assets/7e9d871a-0391-43be-a826-08486ef1d562" />
<img width="200" height="200" alt="virusTotal" src="https://github.com/user-attachments/assets/f3d7cb97-d890-4458-abbb-fd29cde3d7a9" />

- Microsoft Azure
- Microsoft Defender for Endpoint
- Windows 11
- KQL
- VirusTotal
- AbuseIPDB
  
## Executive Summary
Incident ID: INC0002-2025-1119 <br>
Severity: **Critical** <br>
Status: Resolved <br>
Analyst Assigned: `Fasi Sika` 

### Key Findings
Compromised employee credentials were reused to regain access to the internal network following a 72-hour dwell period. The threat actor was able to move laterally within the environment by accessing an internal file server using an administrator account. While on the file server, the attacker conducted discovery activities to better understand the environment and leveraged native system tools to carry out their attack. Sensitive business documents, email archives, employee personal information, and credentials were copied to a hidden staging directory and exfiltrated to an external cloud service. Logs also indicate that the attacker established persistence by modifying registry run keys and attempted to evade detection by deleting command history

The full investigation report can be read [here]()

<img width="1536" height="1024" alt="9ca6eef1-d450-4c60-a89e-a638ba7eb18f" src="https://github.com/user-attachments/assets/d1b3c857-3455-46b7-b491-c9da0a851a53" />

### Immediate Actions
- Identified and isolated affected systems
- Reset credentials on compromised accounts and force 
- Blocked IP addresses utilized by threat actor
- Preserved forensic evidence and endpoint telemetry for further analysis

### Business Impact
With confirmation that sensitive internal data was exfiltrated, this incident posed significant risk to the organization. Stolen data included internal backups, financial information, business partner documentation, employee credentials, and email archives. While no operational outage occurred, the exposure of this data introduced elevated risk related to trust, compliance, and potential follow-on attack

A more detailed analysis of the business impact can be read [here]()

## Credit
This is part two of a four part threat hunt. 

Part 1: [Port of Entry]() <br> 
Part 2: Cargo Hold <br>
Part 3: Bridge Takeover (wip) <br>
Part 4: Dead in the Water (wip) <br>

Thank you Mohammed A for creating this series. <br>
Support the creator below:
- [LinkedIn](https://www.linkedin.com/in/MohammedSancLogic/)
- [YouTube](https://www.youtube.com/@SancLogic)
- [Portfolio](https://sanclogic.com/)
