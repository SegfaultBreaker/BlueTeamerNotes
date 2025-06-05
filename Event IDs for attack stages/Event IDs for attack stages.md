## Security Auditing Events (Core User, Account & Process Monitoring)

| Event ID | Provider                            | Description                                                  | Security Use Case                                         |
|----------|-----------------------------------|--------------------------------------------------------------|----------------------------------------------------------|
| 4624     | Microsoft-Windows-Security-Auditing | An account was successfully logged on                        | Track successful user logons                              |
| 4625     | Microsoft-Windows-Security-Auditing | An account failed to log on                                  | Detect brute force or unauthorized access attempts       |
| 4634     | Microsoft-Windows-Security-Auditing | An account was logged off                                    | Track user logoffs                                        |
| 4647     | Microsoft-Windows-Security-Auditing | User initiated logoff                                        | User session tracking                                    |
| 4648     | Microsoft-Windows-Security-Auditing | A logon was attempted using explicit credentials            | Detect lateral movement and credential misuse            |
| 4672     | Microsoft-Windows-Security-Auditing | Special privileges assigned to new logon                     | Detect privilege escalation                               |
| 4688     | Microsoft-Windows-Security-Auditing | A new process has been created                               | Monitor process creation                                  |
| 4689     | Microsoft-Windows-Security-Auditing | A process has exited                                        | Monitor process termination                               |
| 4697     | Microsoft-Windows-Security-Auditing | A service was installed                                     | Detect persistence via new services                       |
| 4698     | Microsoft-Windows-Security-Auditing | A scheduled task was created                                | Detect persistence via scheduled tasks                   |
| 4699     | Microsoft-Windows-Security-Auditing | A scheduled task was deleted                                | Detect task removal or cleanup attempts                   |
| 4700     | Microsoft-Windows-Security-Auditing | A scheduled task was enabled                                | Persistence detection                                    |
| 4701     | Microsoft-Windows-Security-Auditing | A scheduled task was disabled                               | Possible attacker cleanup                                 |
| 4720     | Microsoft-Windows-Security-Auditing | A user account was created                                  | Detect creation of new user accounts                      |
| 4722     | Microsoft-Windows-Security-Auditing | A user account was enabled                                  | Track account enable events                               |
| 4723     | Microsoft-Windows-Security-Auditing | An attempt was made to change an account’s password        | Detect password changes                                   |
| 4724     | Microsoft-Windows-Security-Auditing | An attempt was made to reset an account’s password         | Detect password resets                                   |
| 4725     | Microsoft-Windows-Security-Auditing | A user account was disabled                                 | Account disablement or lockout                            |
| 4726     | Microsoft-Windows-Security-Auditing | A user account was deleted                                  | Account removal, possible attacker cleanup               |
| 4732     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled local group       | Detect privilege escalation                              |
| 4733     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled local group   | Group membership changes                                 |
| 4740     | Microsoft-Windows-Security-Auditing | A user account was locked out                               | Detect brute force lockouts                              |
| 4767     | Microsoft-Windows-Security-Auditing | A user account was unlocked                                | Unlock event tracking                                    |
| 4768     | Microsoft-Windows-Security-Auditing | A Kerberos authentication ticket (TGT) was requested      | Track Kerberos authentications                           |
| 4769     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was requested                    | Monitor service authentications                          |
| 4771     | Microsoft-Windows-Security-Auditing | Kerberos pre-authentication failed                         | Detect failed Kerberos auth attempts                     |
| 4776     | Microsoft-Windows-Security-Auditing | The domain controller attempted to validate credentials    | Domain authentication attempts                           |
| 4781     | Microsoft-Windows-Security-Auditing | The name of an account was changed                         | Detect account renaming                                  |
| 4794     | Microsoft-Windows-Security-Auditing | An attempt was made to set the Directory Services Restore Mode password | Possible attack or recovery attempts            |
| 4800     | Microsoft-Windows-Security-Auditing | The workstation was locked                                 | User activity tracking                                  |
| 4801     | Microsoft-Windows-Security-Auditing | The workstation was unlocked                               | User activity tracking                                  |
| 4902     | Microsoft-Windows-Security-Auditing | The Per-user audit policy table was created                | Audit policy changes                                    |
| 4904     | Microsoft-Windows-Security-Auditing | An attempt was made to register a security event source   | Detect attempts to tamper with event logs                |
| 4905     | Microsoft-Windows-Security-Auditing | An attempt was made to unregister a security event source | Detect log tampering                                    |
| 4906     | Microsoft-Windows-Security-Auditing | The Windows Firewall settings were changed                | Detect firewall rule changes                             |
| 4946     | Microsoft-Windows-Security-Auditing | A change has been made to Windows Firewall exception list | Firewall exception modifications                         |
| 4956     | Microsoft-Windows-Security-Auditing | A rule was added to the Windows Firewall exception list   | Firewall rule additions                                 |
| 4957     | Microsoft-Windows-Security-Auditing | A rule was deleted from the Windows Firewall exception list | Firewall rule deletions                                |
| 4960     | Microsoft-Windows-Security-Auditing | IPsec dropped a packet due to failed negotiation           | Possible blocked malicious traffic                       |
| 1102     | Microsoft-Windows-Security-Auditing | The audit log was cleared                                  | Possible attacker cleanup                                |


## Active Directory & Group Policy Related Events

| Event ID | Provider                            | Description                                                     | Security Use Case                                             |
|----------|-----------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| 5136     | Microsoft-Windows-Security-Auditing | A directory service object was modified                         | Detect AD object changes (users, computers, groups)          |
| 5137     | Microsoft-Windows-Security-Auditing | A directory service object was created                          | Track creation of AD objects                                  |
| 5138     | Microsoft-Windows-Security-Auditing | A directory service object was undeleted                        | Detect object recovery                                        |
| 5139     | Microsoft-Windows-Security-Auditing | A directory service object was moved                            | Track AD object moves                                        |
| 5141     | Microsoft-Windows-Security-Auditing | A directory service object was deleted                          | Detect AD object deletions                                    |
| 4742     | Microsoft-Windows-Security-Auditing | A computer account was changed                                  | Detect changes to computer accounts                           |
| 4743     | Microsoft-Windows-Security-Auditing | A computer account was deleted                                  | Detect deletion of computer accounts                          |
| 4744     | Microsoft-Windows-Security-Auditing | A security-disabled local group was created                     | Track creation of local groups                                |
| 4745     | Microsoft-Windows-Security-Auditing | A security-disabled local group was changed                     | Track changes to local groups                                 |
| 4746     | Microsoft-Windows-Security-Auditing | A security-disabled local group was deleted                     | Track deletion of local groups                                |
| 4747     | Microsoft-Windows-Security-Auditing | A security-enabled global group was created                     | Detect new global groups                                      |
| 4748     | Microsoft-Windows-Security-Auditing | A security-enabled global group was changed                     | Track global group changes                                    |
| 4749     | Microsoft-Windows-Security-Auditing | A security-enabled global group was deleted                     | Track deletion of global groups                               |
| 4750     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was created                  | Detect new universal groups                                   |
| 4751     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was changed                  | Track universal group changes                                 |
| 4752     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was deleted                  | Track deletion of universal groups                            |
| 4753     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled global group           | Privilege escalation detection                               |
| 4754     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled global group       | Group membership removal                                     |
| 4755     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled universal group        | Group membership changes                                     |
| 4756     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled universal group    | Group membership changes                                     |
| 4757     | Microsoft-Windows-Security-Auditing | A member was added to a security-disabled local group           | Group membership changes                                     |
| 4758     | Microsoft-Windows-Security-Auditing | A member was removed from a security-disabled local group       | Group membership changes                                     |
| 4761     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket request failed                        | Authentication failure detection                             |
| 4762     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was renewed                            | Ticket renewal tracking                                     |
| 4763     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was renewed after forwardable         | Advanced ticket tracking                                     |
| 4764     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was requested with a different name   | Ticket misuse detection                                     |
| 4798     | Microsoft-Windows-Security-Auditing | A user's local group membership was enumerated                  | Detect reconnaissance of group memberships                  |
| 4799     | Microsoft-Windows-Security-Auditing | A security-enabled local group membership was enumerated        | Detect reconnaissance of privileged groups                  |
| 4864     | Microsoft-Windows-Security-Auditing | A basic application group was created                            | Group creation monitoring                                   |
| 4865     | Microsoft-Windows-Security-Auditing | A basic application group was changed                            | Group modification detection                                |
| 4866     | Microsoft-Windows-Security-Auditing | A basic application group was deleted                            | Group deletion monitoring                                   |
| 4907     | Microsoft-Windows-Security-Auditing | Auditing settings on object were changed                         | Audit policy monitoring                                     |
| 4739     | Microsoft-Windows-Security-Auditing | Domain Policy was changed                                        | Detect Group Policy changes                                 |
| 1644     | Microsoft-Windows-GroupPolicy       | Group Policy settings were processed                             | Monitor Group Policy application                            |

## Windows Defender & Antivirus Events

| Event ID | Provider                          | Description                                                  | Security Use Case                                              |
|----------|-----------------------------------|--------------------------------------------------------------|----------------------------------------------------------------|
| 1116     | Microsoft-Windows-Windows Defender | Malware detected                                             | Detection of malicious software                                |
| 1117     | Microsoft-Windows-Windows Defender | Malware detection remediation failed                         | Failed attempt to clean malware                                |
| 1118     | Microsoft-Windows-Windows Defender | Malware detection remediation succeeded                      | Successful remediation of malware                              |
| 1119     | Microsoft-Windows-Windows Defender | Malware action was taken                                     | Action applied on malicious item                               |
| 1120     | Microsoft-Windows-Windows Defender | Malware action failed                                        | Failed response to threat                                      |
| 1121     | Microsoft-Windows-Windows Defender | Malware action succeeded                                     | Confirmation of malware action                                 |
| 1123     | Microsoft-Windows-Windows Defender | Malicious behavior prevented                                 | Real-time protection intervened                                |
| 2000     | Microsoft-Windows-Windows Defender | Antivirus service started                                    | Track AV agent activity                                        |
| 2001     | Microsoft-Windows-Windows Defender | Antivirus service stopped                                    | Detect service interruption                                    |
| 3002     | Microsoft-Windows-Windows Defender | Threat removed by user or Defender                           | Manual remediation detected                                    |
| 5007     | Microsoft-Windows-Windows Defender | Configuration change                                         | Monitor changes to Defender config (e.g., exclusions)          |
| 5010     | Microsoft-Windows-Windows Defender | Signature update started                                     | AV update tracking                                             |
| 5012     | Microsoft-Windows-Windows Defender | Signature update completed                                   | AV update successful                                           |
| 1006     | Microsoft-Windows-Windows Defender | Real-time protection disabled                                | Protection status monitoring                                   |
| 1007     | Microsoft-Windows-Windows Defender | Real-time protection enabled                                 | AV re-enabled                                                 |
| 1010     | Microsoft-Windows-Windows Defender | Scan started                                                 | AV initiated scan                                              |
| 1011     | Microsoft-Windows-Windows Defender | Scan completed                                               | Scan results tracking                                          |
| 1015     | Microsoft-Windows-Windows Defender | Scan cancelled                                               | Cancelled or interrupted scans                                 |
| 1016     | Microsoft-Windows-Windows Defender | Scan failed                                                  | Unsuccessful scan attempt                                      |
| 3004     | Microsoft-Windows-Windows Defender | Threat detected (manual scan)                                | Scan-time malware detection                                   |
| 5001     | Microsoft-Windows-Windows Defender | Tamper protection disabled                                   | High-severity alert — protection bypass attempt                |
| 5004     | Microsoft-Windows-Windows Defender | Exclusion added or changed                                   | Potential evasion of AV protection                            |

## PowerShell & Script-Based Attack Detection

| Event ID | Provider                                   | Description                                                        | Security Use Case                                                  |
|----------|--------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------|
| 400      | Microsoft-Windows-PowerShell               | Engine state changed (started)                                     | Track start of PowerShell engine sessions                           |
| 403      | Microsoft-Windows-PowerShell               | PowerShell engine state changed (stopped)                          | Track termination of PowerShell sessions                            |
| 600      | Microsoft-Windows-PowerShell               | Command started                                                    | Detect script or cmdlet execution                                   |
| 800      | Microsoft-Windows-PowerShell               | Pipeline execution details                                         | Monitor script execution                                            |
| 403      | Microsoft-Windows-PowerShell               | PowerShell engine initialization                                   | Script-based execution tracking                                     |
| 4103     | Microsoft-Windows-PowerShell               | Module logging (record of loaded modules)                          | Detect loading of potentially malicious or unusual modules          |
| 4104     | Microsoft-Windows-PowerShell               | Script Block Logging: code executed                                | Capture full script blocks, including obfuscated or encoded scripts |
| 4105     | Microsoft-Windows-PowerShell               | Script Block Logging: script block signature validation failed     | Tampered or unsigned script detection                              |
| 4106     | Microsoft-Windows-PowerShell               | Script Block Logging: script block invocation                      | Advanced script execution monitoring                               |
| 53504    | Microsoft-Windows-PowerShell/Operational   | Remote command executed                                            | Detect remote PowerShell sessions (e.g., PS Remoting)               |
| 4100     | Microsoft-Windows-PowerShell               | PowerShell provider started                                        | Execution context identification                                   |
| 4101     | Microsoft-Windows-PowerShell               | PowerShell provider finished                                       | Session conclusion tracking                                        |
| 4698     | Microsoft-Windows-Security-Auditing        | Scheduled task created (script persistence)                        | Detect use of PowerShell in scheduled tasks                         |
| 7045     | Microsoft-Windows-Security-Auditing        | New service installed (e.g., using PowerShell as service)          | Script-based persistence or lateral movement                        |

## WMI, Sysinternals & System Tampering Events

| Event ID | Provider                                 | Description                                                       | Security Use Case                                                    |
|----------|------------------------------------------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| 5861     | Microsoft-Windows-WMI-Activity           | WMI consumer started                                              | Detect WMI-based persistence or execution                           |
| 5860     | Microsoft-Windows-WMI-Activity           | WMI provider started                                              | Monitor WMI infrastructure use                                      |
| 5857     | Microsoft-Windows-WMI-Activity           | WMI provider unloaded                                             | Monitor WMI lifecycle                                               |
| 5858     | Microsoft-Windows-WMI-Activity           | WMI activity operation failure                                    | Detect failed WMI attempts                                          |
| 4688     | Microsoft-Windows-Security-Auditing      | New process created (Sysinternals tools like PsExec, etc.)       | Detect execution of powerful administrative tools                   |
| 7040     | Microsoft-Windows-Service Control Manager| Service change configuration (manual to auto or vice versa)       | Detect suspicious service config changes                            |
| 7045     | Microsoft-Windows-Security-Auditing      | A new service was installed                                       | Persistence or tool deployment detection                           |
| 4697     | Microsoft-Windows-Security-Auditing      | Service installation attempt                                      | Persistence and lateral movement indication                         |
| 4720     | Microsoft-Windows-Security-Auditing      | New user account created                                          | Local persistence or backdoor accounts                             |
| 4722     | Microsoft-Windows-Security-Auditing      | Account enabled                                                   | Re-enabling of disabled backdoor accounts                          |
| 1102     | Microsoft-Windows-Security-Auditing      | Security log cleared                                              | Covering attacker tracks                                            |
| 7042     | Microsoft-Windows-Service Control Manager| System is entering Safe Mode                                      | Possible evasion attempt                                            |
| 7035     | Microsoft-Windows-Service Control Manager| Service control requested (start/stop services)                   | Monitor tampering with AV or critical services                      |
| 7036     | Microsoft-Windows-Service Control Manager| Service state changed                                             | Detect services going down unexpectedly                            |
| 5033     | Microsoft-Windows-Windows Firewall       | Firewall rule added                                               | Potential malicious firewall bypass                                |
| 5031     | Microsoft-Windows-Windows Firewall       | Application blocked by firewall                                   | Useful in detecting blocked malware communication attempts         |
| 6416     | Microsoft-Windows-Security-Auditing      | Security system extension loaded                                  | Potential kernel-level backdoors or rootkits                       |
| 6410     | Microsoft-Windows-Security-Auditing      | Code integrity violation                                          | Kernel-level tampering detection                                   |
| 3006     | Microsoft-Windows-Application Experience | A program was blocked from executing                              | Application whitelisting enforcement                               |

## Network Connections & Remote Access Detection

| Event ID | Provider                              | Description                                                     | Security Use Case                                                  |
|----------|----------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------------|
| 4624     | Microsoft-Windows-Security-Auditing    | Successful logon                                               | Detect remote logons (Type 3, Type 10 = network, RDP)               |
| 4625     | Microsoft-Windows-Security-Auditing    | Failed logon                                                   | Detect brute-force or failed remote access                          |
| 4648     | Microsoft-Windows-Security-Auditing    | Logon with explicit credentials                                | Detect pass-the-hash/ticket/credential use                         |
| 4672     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                       | High-privileged session detection                                   |
| 4778     | Microsoft-Windows-Security-Auditing    | RDP session reconnected                                        | RDP tracking                                                        |
| 4779     | Microsoft-Windows-Security-Auditing    | RDP session disconnected                                       | RDP tracking                                                        |
| 5140     | Microsoft-Windows-Security-Auditing    | Network share object accessed                                  | Detect access to administrative or sensitive shares                 |
| 5145     | Microsoft-Windows-Security-Auditing    | Detailed share access attempt                                  | Forensic detail on share access attempts                            |
| 5156     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: Allowed network connection         | Track allowed outbound connections                                  |
| 5158     | Microsoft-Windows-Security-Auditing    | WFP: connection permit                                          | Map lateral movement, C2 beacons, etc.                              |
| 5152     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: Blocked network connection         | Detect blocked malicious traffic attempts                           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                      | Track domain name resolution — useful for identifying C2 domains    |
| 6013     | Microsoft-Windows-TerminalServices-LocalSessionManager | User session duration                             | RDP session auditing                                                |
| 1024     | Microsoft-Windows-TLS-SSL              | TLS handshake initiated                                        | Detect encrypted communication initiation (can be C2)              |
| 10000    | Microsoft-Windows-TCPIP                | Outbound connection initiated                                  | See which IPs/ports are contacted                                  |
| 5157     | Microsoft-Windows-Security-Auditing    | Packet dropped                                                 | Firewall dropped malicious or unauthorized connection              |
| 5379     | Microsoft-Windows-Security-Auditing    | Credential validation via NPS                                  | VPN, wireless auth — useful for remote access forensics             |
| 4647     | Microsoft-Windows-Security-Auditing    | User initiated logoff                                          | Track session terminations                                          |
| 4769     | Microsoft-Windows-Security-Auditing    | Kerberos service ticket requested                              | Monitor service access and lateral movement                         |
| 4771     | Microsoft-Windows-Security-Auditing    | Kerberos pre-auth failed                                       | Password guessing, replay, or time-skew attacks                     |
| 1149     | Microsoft-Windows-Security-Auditing    | RDP connection was established                                 | RDP connection successfull / established                            |

## Logon Types, Scheduled Tasks & Registry Monitoring

| Event ID | Provider                              | Description                                                      | Security Use Case                                                   |
|----------|----------------------------------------|------------------------------------------------------------------|----------------------------------------------------------------------|
| 4624     | Microsoft-Windows-Security-Auditing    | Successful logon                                                 | Track account logons (critical for correlation)                     |
| 4625     | Microsoft-Windows-Security-Auditing    | Failed logon                                                     | Brute-force, spraying, or invalid credential use                    |
| 4634     | Microsoft-Windows-Security-Auditing    | Logoff                                                           | Account session monitoring                                          |
| 4647     | Microsoft-Windows-Security-Auditing    | User initiated logoff                                            | Distinguish user from forced logoff                                 |
| 4648     | Microsoft-Windows-Security-Auditing    | Logon using explicit credentials                                 | Pass-the-Hash, runas, etc.                                          |
| 4672     | Microsoft-Windows-Security-Auditing    | Admin privileges assigned at logon                               | High-value account activity                                         |
| 4627     | Microsoft-Windows-Security-Auditing    | Group membership info during logon                               | Check what groups were active                                      |
| 4768     | Microsoft-Windows-Security-Auditing    | Kerberos TGT requested                                           | Track domain authentication                                        |
| 4769     | Microsoft-Windows-Security-Auditing    | Kerberos service ticket requested                                | Monitor service access attempts                                    |
| 4771     | Microsoft-Windows-Security-Auditing    | Kerberos pre-authentication failed                               | Replay, time-based, or brute-force Kerberos attacks                |
| 4776     | Microsoft-Windows-Security-Auditing    | Credential validation via NTLM                                   | Detect legacy auth use and credential attacks                      |
| 4698     | Microsoft-Windows-Security-Auditing    | Scheduled task created                                           | Persistence detection (e.g., PowerShell or scripts scheduled)       |
| 4699     | Microsoft-Windows-Security-Auditing    | Scheduled task deleted                                           | Hiding persistence                                                  |
| 4700     | Microsoft-Windows-Security-Auditing    | Scheduled task enabled                                           | Reactivation of dormant persistence                                |
| 4701     | Microsoft-Windows-Security-Auditing    | Scheduled task disabled                                          | Disabling a legitimate task to hide behavior                       |
| 4657     | Microsoft-Windows-Security-Auditing    | Registry key or value modified                                   | Detect tampering (e.g., disabling AV, autoruns)                    |
| 4660     | Microsoft-Windows-Security-Auditing    | Object deleted                                                   | Registry persistence cleanup                                       |
| 13       | Microsoft-Windows-Sysmon               | Registry value set                                               | Deeper registry tampering (including stealthy changes)             |
| 14       | Microsoft-Windows-Sysmon               | Registry key created                                             | Detect malicious persistence keys                                  |
| 15       | Microsoft-Windows-Sysmon               | Registry key deleted                                             | Cleanup or malware removal behavior                                |

## Account Manipulation & Privilege Escalation Detection

| Event ID | Provider                              | Description                                                       | Security Use Case                                                    |
|----------|----------------------------------------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| 4720     | Microsoft-Windows-Security-Auditing    | A user account was created                                        | Rogue account creation for persistence                              |
| 4722     | Microsoft-Windows-Security-Auditing    | A user account was enabled                                        | Reactivation of a dormant or backdoor account                       |
| 4723     | Microsoft-Windows-Security-Auditing    | A user attempted to change own password                           | Account takeover detection                                           |
| 4724     | Microsoft-Windows-Security-Auditing    | Attempt to reset another user’s password                          | Lateral movement or privilege escalation attempt                     |
| 4725     | Microsoft-Windows-Security-Auditing    | User account disabled                                             | Deactivation of legitimate users (DOS or cover-up)                  |
| 4726     | Microsoft-Windows-Security-Auditing    | User account deleted                                              | Hide traces of malicious accounts                                   |
| 4731     | Microsoft-Windows-Security-Auditing    | A security-enabled local group was created                        | Persistence through group abuse                                     |
| 4732     | Microsoft-Windows-Security-Auditing    | A member was added to a security-enabled local group              | Escalation (e.g., user added to Administrators group)               |
| 4733     | Microsoft-Windows-Security-Auditing    | A member was removed from a security-enabled local group          | Cleanup of escalation or lateral movement                           |
| 4735     | Microsoft-Windows-Security-Auditing    | Security-enabled local group modified                             | Group tampering for stealth or persistence                          |
| 4737     | Microsoft-Windows-Security-Auditing    | Security-enabled global group modified                            | Domain-level escalation detection                                   |
| 4756     | Microsoft-Windows-Security-Auditing    | Security-enabled universal group created                          | High-level domain group creation                                    |
| 4757     | Microsoft-Windows-Security-Auditing    | Member added to universal group                                   | Domain-wide permission escalation                                   |
| 4758     | Microsoft-Windows-Security-Auditing    | Member removed from universal group                               | Cleanup or stealthy privilege removal                               |
| 4670     | Microsoft-Windows-Security-Auditing    | Permissions on an object were changed                             | Detect sensitive file/folder ACL changes                            |
| 4671     | Microsoft-Windows-Security-Auditing    | Application attempted to access a protected object                | Privilege escalation attempt                                        |
| 4964     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                          | Detection of logon with high privileges                             |
| 4902     | Microsoft-Windows-Security-Auditing    | Audit policy was changed                                          | Potential log tampering / stealth                                    |
| 4612     | Microsoft-Windows-Security-Auditing    | Internal security authority (LSASS) initialization                | Monitoring changes to authentication mechanisms                     |

## Process Injection, Memory Tampering & Defense Evasion

| Event ID | Provider                              | Description                                                         | Security Use Case                                                       |
|----------|----------------------------------------|---------------------------------------------------------------------|---------------------------------------------------------------------------|
| 10       | Microsoft-Windows-Sysmon               | Process accessed another process                                    | Detect process injection (e.g., `svchost` accessing `lsass`)             |
| 7        | Microsoft-Windows-Sysmon               | Image loaded                                                        | Detect DLL injection, sideloading, unsigned libraries                    |
| 8        | Microsoft-Windows-Sysmon               | CreateRemoteThread                                                  | Detect classic injection techniques                                      |
| 9        | Microsoft-Windows-Sysmon               | RawAccessRead                                                       | Detect memory scraping (e.g., Mimikatz reading LSASS)                   |
| 6        | Microsoft-Windows-Sysmon               | Driver loaded                                                       | Detect suspicious or unsigned drivers (rootkits)                        |
| 11       | Microsoft-Windows-Sysmon               | File created                                                        | Track payload drop before memory execution                              |
| 15       | Microsoft-Windows-Sysmon               | Registry key deleted                                                | Persistence removal or stealth                                          |
| 13       | Microsoft-Windows-Sysmon               | Registry value set                                                  | Registry tampering for stealth or persistence                           |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                                    | Detect suspicious processes (e.g., `rundll32`, `regsvr32`, `mshta`)     |
| 4688     | Microsoft-Windows-Security-Auditing    | A new process has been created                                      | Base process tracking (can correlate with Sysmon)                       |
| 1116     | Microsoft-Windows-Windows Defender     | Malware detected                                                    | Antivirus alert logging                                                 |
| 1117     | Microsoft-Windows-Windows Defender     | Malware action taken (quarantined, etc.)                            | Confirm successful detection                                             |
| 5007     | Microsoft-Windows-Windows Defender     | Windows Defender configuration change                               | Detect tampering or disabling Defender                                 |
| 5010     | Microsoft-Windows-Windows Defender     | Antimalware engine health changed                                   | Indicator of compromise, disabling AV                                  |
| 7036     | Microsoft-Windows-Service Control Manager| Service stopped or started                                        | Suspicious AV or EDR service disablement                               |
| 4697     | Microsoft-Windows-Security-Auditing    | A service was installed                                             | Malicious services or persistence                                       |
| 6416     | Microsoft-Windows-Security-Auditing    | Code integrity determined an unsigned driver loaded                 | Kernel-level tampering                                                  |
| 3002     | Microsoft-Windows-CodeIntegrity        | Code integrity check failed                                         | Detect tampered or untrusted modules                                   |
| 3004     | Microsoft-Windows-CodeIntegrity        | Unsigned driver blocked                                             | Stop of kernel-level threats                                            |

## Exfiltration, Staging, and Compression Detection

| Event ID | Provider                              | Description                                                     | Security Use Case                                                     |
|----------|----------------------------------------|------------------------------------------------------------------|------------------------------------------------------------------------|
| 4663     | Microsoft-Windows-Security-Auditing    | File object accessed                                             | Detect access to sensitive files (pre-exfil)                          |
| 4656     | Microsoft-Windows-Security-Auditing    | Handle to an object was requested                                | Identify intent to access or move data                                |
| 11       | Microsoft-Windows-Sysmon               | File created                                                     | Track new archive files like `.zip`, `.rar`, `.7z`                    |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                                 | Detect use of tools like `rar.exe`, `7z.exe`, `winrar.exe`, `scp`     |
| 3        | Microsoft-Windows-Sysmon               | Network connection                                               | Monitor large/suspicious outbound connections                         |
| 5156     | Microsoft-Windows-Security-Auditing    | WFP: Allowed connection                                          | Spot FTP/SFTP/HTTP connections used for exfiltration                  |
| 5158     | Microsoft-Windows-Security-Auditing    | WFP: Connection allowed (low-level)                              | Useful for mapping protocol types and targets                         |
| 5152     | Microsoft-Windows-Security-Auditing    | WFP: Blocked connection                                          | Blocked exfil attempts (misconfigured tools, firewalls)               |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                        | Lookups for domains related to drop zones (e.g., `transfer.sh`)       |
| 10000    | Microsoft-Windows-TCPIP                | Outbound TCP connection                                          | Track suspicious external connections to ports 21 (FTP), 22, 443      |
| 5145     | Microsoft-Windows-Security-Auditing    | Network share object accessed                                    | Exfiltration via SMB shares                                          |
| 7045     | Microsoft-Windows-Service Control Manager | Service installed                                               | Suspicious services used to move or stage data                        |
| 1102     | Microsoft-Windows-Eventlog             | Security log cleared                                             | Post-exfil cleanup                                                    |
| 4688     | Microsoft-Windows-Security-Auditing    | A new process has been created                                   | Detect use of archiving + transfer tools                             |


## Command & Control (C2) Communications Detection

| Event ID | Provider                              | Description                                                      | Security Use Case                                                   |
|----------|----------------------------------------|------------------------------------------------------------------|----------------------------------------------------------------------|
| 3        | Microsoft-Windows-Sysmon               | Network connection                                               | Detect callback IPs or known C2 ports (e.g., 4444, 8080, 53)         |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                                 | Identify C2 agents (e.g., `powershell`, `mshta`, `rundll32`)         |
| 8        | Microsoft-Windows-Sysmon               | CreateRemoteThread                                               | Used in Cobalt Strike/Metasploit for injection                      |
| 7        | Microsoft-Windows-Sysmon               | Image loaded                                                     | Detect malicious DLLs used by C2 agents                             |
| 10       | Microsoft-Windows-Sysmon               | Process accessed another process                                 | Common in malware staging and injection                             |
| 5145     | Microsoft-Windows-Security-Auditing    | Network share accessed                                           | Peer-to-peer or lateral movement between agents                     |
| 5156     | Microsoft-Windows-Security-Auditing    | Allowed network connection                                       | Spot connections to C2 servers or beacon IPs                        |
| 5158     | Microsoft-Windows-Security-Auditing    | Low-level outbound connection                                    | Monitor stealthy outbound traffic                                   |
| 5059     | Microsoft-Windows-WMI-Activity         | WMI consumer binding                                             | Persistence / lateral tool used by agents                           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                        | Beacon domains, FastFlux, DGAs (e.g., `.xyz`, `.top`, etc.)         |
| 10000    | Microsoft-Windows-TCPIP                | Outbound TCP connection                                          | Catch outbound C2 to nonstandard ports                              |
| 4688     | Microsoft-Windows-Security-Auditing    | Process creation                                                 | Initial launch of agent, C2 loader (e.g., `powershell -enc`)         |
| 4104     | Microsoft-Windows-PowerShell/Operational | Script block logging                                           | Detect encoded or obfuscated C2 script payloads                     |
| 4103     | Microsoft-Windows-PowerShell/Operational | Command invocation                                              | Logs each PowerShell command                                         |
| 3002     | Microsoft-Windows-CodeIntegrity        | Driver signature check failed                                    | Malware driver load (e.g., rootkit C2 channels)                     |
| 7045     | Microsoft-Windows-Service Control Manager | New service installed                                          | C2 agents installed as services                                     |

## Fileless Attacks, LOLBins, and Living-off-the-Land Detection

| Event ID | Provider                              | Description                                                   | Security Use Case                                                      |
|----------|----------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
| 4688     | Microsoft-Windows-Security-Auditing    | A new process has been created                                 | Detect usage of LOLBins (e.g., `regsvr32`, `mshta`, `rundll32`)        |
| 4104     | Microsoft-Windows-PowerShell/Operational | PowerShell script block logging                               | Detect obfuscated or suspicious scripts executed in memory            |
| 4103     | Microsoft-Windows-PowerShell/Operational | PowerShell command invocation logging                         | Monitor individual PowerShell commands for suspicious usage           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                    | Detect DNS tunneling or command-and-control via DNS                    |
| 7        | Microsoft-Windows-Sysmon               | Image loaded                                                 | Detect suspicious loading of LOLBin payloads or scripts               |
| 10       | Microsoft-Windows-Sysmon               | Process accessed another process                             | Identify process hollowing or injection through LOLBins               |
| 11       | Microsoft-Windows-Sysmon               | File created                                               | Detect files dropped by LOLBins or related malware                     |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                           | Track usage of living-off-the-land binaries                            |
| 3002     | Microsoft-Windows-CodeIntegrity        | Code integrity check failed                                | Detect execution of unsigned or modified LOLBin code                  |
| 5007     | Microsoft-Windows-Windows Defender     | Windows Defender configuration change                     | Detect disabling of AV or tampering for fileless attack facilitation  |
| 5059     | Microsoft-Windows-WMI-Activity         | WMI consumer binding                                     | Detect persistence or execution through WMI scripting                |
| 4697     | Microsoft-Windows-Security-Auditing    | A service was installed                                   | Detect installation of suspicious services used by LOLBins          |

## Network Layer Forensics and Advanced Threat Hunting

| Event ID | Provider                              | Description                                                     | Security Use Case                                                     |
|----------|----------------------------------------|-----------------------------------------------------------------|---------------------------------------------------------------------|
| 3        | Microsoft-Windows-Sysmon               | Network connection                                             | Detect suspicious outbound/inbound TCP/UDP connections             |
| 5156     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: allowed connection                 | Monitor allowed network flows for anomalous patterns               |
| 5158     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: permitted packet                    | Track network traffic at granular level                             |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                    | Identify domain queries to suspicious/malicious domains            |
| 8004     | Microsoft-Windows-DNS-Client           | DNS response                                                | Correlate DNS queries with responses for anomaly detection         |
| 1100     | Microsoft-Windows-Eventlog             | Event log cleared                                             | Potential indicator of attempts to erase network forensic data     |
| 5059     | Microsoft-Windows-WMI-Activity         | WMI consumer binding                                         | Detect lateral movement or persistence mechanisms using WMI        |
| 4648     | Microsoft-Windows-Security-Auditing    | Logon with explicit credentials                              | Track network authentication attempts                              |
| 4672     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                    | Monitor privileged network logons                                  |
| 5152     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: blocked connection               | Detect blocked outbound connections — possible C2 or exfiltration  |
| 1102     | Microsoft-Windows-Eventlog             | Security log cleared                                         | Potential log tampering                                             |
| 7045     | Microsoft-Windows-Service Control Manager | New service installed                                     | Detect rogue network services or proxies                           |
| 7040     | Microsoft-Windows-Service Control Manager | Service start type changed                                 | Could indicate network service behavior modification               |

## USB, Device, and Peripheral Activity Monitoring

| Event ID | Provider                              | Description                                                   | Security Use Case                                                      |
|----------|----------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
| 1006     | Microsoft-Windows-DriverFrameworks-UserMode | Device connected                                          | Detect USB device insertion                                           |
| 1007     | Microsoft-Windows-DriverFrameworks-UserMode | Device disconnected                                       | Detect USB device removal                                            |
| 2003     | Microsoft-Windows-Partition/Diagnostic   | Disk volume mounted                                       | Identify removable media mounting                                   |
| 6416     | Microsoft-Windows-Security-Auditing      | Device connected                                          | Track new device connection for audit                               |
| 4663     | Microsoft-Windows-Security-Auditing      | File object accessed                                      | Detect file access on removable devices                             |
| 4656     | Microsoft-Windows-Security-Auditing      | Handle to an object requested                            | Monitor operations on files stored on external devices             |
| 4660     | Microsoft-Windows-Security-Auditing      | File deleted                                            | Detect deletion on removable media                                 |
| 4664     | Microsoft-Windows-Security-Auditing      | Object operation attempted                               | Detect write attempts to USB or external drives                    |
| 4697     | Microsoft-Windows-Security-Auditing      | A service was installed                                 | Detect services related to device management or unauthorized tools |
| 1102     | Microsoft-Windows-Eventlog                 | Security log cleared                                    | Identify potential cover-up post device use                        |
| 7045     | Microsoft-Windows-Service Control Manager  | New service installed                                  | Detect device-related malicious service installations             |

## Windows Defender, Antivirus, and Endpoint Protection Events

| Event ID | Provider                                   | Description                                                  | Security Use Case                                                  |
|----------|--------------------------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| 1116     | Microsoft-Windows-Windows Defender/Operational | Malware detected and cleaned                                 | Detect successful malware removal                                 |
| 1117     | Microsoft-Windows-Windows Defender/Operational | Malware detection failed or remediation failed              | Alert on persistent or resistant malware                          |
| 5001     | Microsoft-Windows-Windows Defender/Operational | Antivirus scan started                                      | Track scheduled or manual scans                                   |
| 5002     | Microsoft-Windows-Windows Defender/Operational | Antivirus scan completed                                   | Confirm scan coverage and timing                                 |
| 5004     | Microsoft-Windows-Windows Defender/Operational | Real-time protection state changed                         | Detect Defender enabling/disabling                               |
| 5007     | Microsoft-Windows-Windows Defender/Operational | Windows Defender configuration changed                     | Spot policy or AV tampering                                      |
| 1110     | Microsoft-Windows-Windows Defender/Operational | Threat remediation status                                  | Monitor remediation outcomes                                     |
| 3004     | Microsoft-Windows-Windows Defender/Operational | Threat detected                                           | Initial malware detection events                                 |
| 1112     | Microsoft-Windows-Windows Defender/Operational | Network inspection detected suspicious network activity    | Detect network-based malware behavior                            |
| 1114     | Microsoft-Windows-Windows Defender/Operational | Real-time protection alert                                 | Immediate alerts on active threats                              |
| 5008     | Microsoft-Windows-Windows Defender/Operational | Antivirus engine update success                            | Verify AV engine currency                                       |

## Application Whitelisting and Code Integrity Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 8004     | Microsoft-Windows-CodeIntegrity        | Code integrity violation                                      | Detect unsigned or tampered binaries execution                      |
| 8003     | Microsoft-Windows-CodeIntegrity        | Code integrity check success                                  | Confirm allowed binaries                                            |
| 8005     | Microsoft-Windows-CodeIntegrity        | Code integrity policy change                                  | Detect changes to whitelisting policies                             |
| 5007     | Microsoft-Windows-Windows Defender     | Configuration change                                         | Spot tampering of Defender/AppLocker settings                       |
| 8000     | Microsoft-Windows-AppLocker             | Executable blocked                                           | Detect blocked application runs                                    |
| 8001     | Microsoft-Windows-AppLocker             | Executable allowed                                           | Confirm allowed application runs                                   |
| 8020     | Microsoft-Windows-AppLocker             | DLL blocked                                                | Detect blocked DLL loads                                           |
| 8021     | Microsoft-Windows-AppLocker             | DLL allowed                                                | Confirm allowed DLL loads                                          |
| 8030     | Microsoft-Windows-AppLocker             | Script blocked                                            | Detect blocked script executions                                  |
| 8031     | Microsoft-Windows-AppLocker             | Script allowed                                            | Confirm allowed script executions                                 |

## User Account and Privilege Management Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 4720     | Microsoft-Windows-Security-Auditing    | User account created                                         | Detect unauthorized user creation                                   |
| 4722     | Microsoft-Windows-Security-Auditing    | User account enabled                                       | Track activation of dormant accounts                                |
| 4723     | Microsoft-Windows-Security-Auditing    | User account password change attempted                     | Detect password change attempts                                     |
| 4724     | Microsoft-Windows-Security-Auditing    | Password reset attempted                                   | Monitor reset of user passwords                                     |
| 4725     | Microsoft-Windows-Security-Auditing    | User account disabled                                      | Detect disabling of user accounts                                   |
| 4726     | Microsoft-Windows-Security-Auditing    | User account deleted                                      | Track account removal                                              |
| 4732     | Microsoft-Windows-Security-Auditing    | Member added to a security-enabled local group            | Detect privilege escalation via group membership                   |
| 4733     | Microsoft-Windows-Security-Auditing    | Member removed from a security-enabled local group        | Monitor privilege revocation                                       |
| 4672     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                  | Identify privileged logons                                         |
| 4768     | Microsoft-Windows-Security-Auditing    | Kerberos authentication ticket requested                  | Track authentication activity                                      |
| 4769     | Microsoft-Windows-Security-Auditing    | Kerberos service ticket requested                         | Monitor service ticket requests                                    |
| 4771     | Microsoft-Windows-Security-Auditing    | Kerberos pre-authentication failed                        | Detect possible brute force or credential attacks                  |
| 4776     | Microsoft-Windows-Security-Auditing    | NTLM authentication attempted                             | Track NTLM auth, often used in lateral movement                    |

## Windows Security and Audit Policy Changes

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 4719     | Microsoft-Windows-Security-Auditing    | System audit policy was changed                              | Detect changes in audit settings that reduce visibility            |
| 4902     | Microsoft-Windows-Security-Auditing    | The audit policy (SACL) on an object was changed             | Monitor SACL tampering on sensitive objects                        |
| 4904     | Microsoft-Windows-Security-Auditing    | Windows Firewall was changed                                 | Detect firewall policy modifications                               |
| 4905     | Microsoft-Windows-Security-Auditing    | Windows Firewall policy was changed                          | Monitor detailed firewall policy changes                          |
| 4715     | Microsoft-Windows-Security-Auditing    | Audit policy change attempted                               | Track attempts to alter audit policies                             |
| 1102     | Microsoft-Windows-Eventlog             | The audit log was cleared                                   | Detect log clearing often used to cover tracks                    |
| 4616     | Microsoft-Windows-Security-Auditing    | System time was changed                                     | Detect time tampering to obfuscate event timelines                |
| 4704     | Microsoft-Windows-Security-Auditing    | User right was assigned                                     | Detect assignment of sensitive user rights                        |
| 4705     | Microsoft-Windows-Security-Auditing    | User right was removed                                     | Monitor removal of user rights                                    |

## Windows Scheduled Tasks and Job Monitoring

| Event ID | Provider                              | Description                                                    | Security Use Case                                                    |
|----------|----------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| 4698     | Microsoft-Windows-Security-Auditing    | Scheduled task created                                       | Detect unauthorized task creation for persistence                  |
| 4699     | Microsoft-Windows-Security-Auditing    | Scheduled task deleted                                       | Track task removal potentially to cover tracks                     |
| 4700     | Microsoft-Windows-Security-Auditing    | Scheduled task enabled                                       | Detect re-enabling of disabled malicious tasks                     |
| 4701     | Microsoft-Windows-Security-Auditing    | Scheduled task disabled                                      | Identify disabling of security or monitoring tasks                 |
| 102      | Microsoft-Windows-TaskScheduler         | Task triggered                                              | Monitor task execution                                             |
| 106      | Microsoft-Windows-TaskScheduler         | Task registration failed                                    | Detect issues or tampering with task registration                  |
| 1102     | Microsoft-Windows-Eventlog               | Security log cleared                                        | Possible cover-up after task activity                              |

## Windows PowerShell and Command Line Activity Monitoring

| Event ID | Provider                              | Description                                                      | Security Use Case                                                    |
|----------|----------------------------------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| 4104     | Microsoft-Windows-PowerShell/Operational | PowerShell script block logging                                   | Capture detailed PowerShell commands executed                      |
| 4103     | Microsoft-Windows-PowerShell/Operational | PowerShell pipeline execution details                            | Monitor pipeline stages for suspicious command chains              |
| 4688     | Microsoft-Windows-Security-Auditing    | Process creation                                                | Detect execution of PowerShell or cmd.exe with suspicious args    |
| 8000     | Microsoft-Windows-PowerShell/Operational | PowerShell transcription started                                | Confirm command logging is enabled                                 |
| 8001     | Microsoft-Windows-PowerShell/Operational | PowerShell transcription stopped                                | Detect transcription service stoppage (possible evasion)          |
| 4105     | Microsoft-Windows-PowerShell/Operational | PowerShell module logging                                        | Track modules loaded into PowerShell                               |
| 400     | Microsoft-Windows-CommandLine/Operational | Command line process tracing                                    | Detect detailed command line activity                              |

## Windows Registry and Configuration Changes

| Event ID | Provider                              | Description                                                   | Security Use Case                                                    |
|----------|----------------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------|
| 4657     | Microsoft-Windows-Security-Auditing    | Registry value modified                                      | Detect changes to critical registry keys                           |
| 4697     | Microsoft-Windows-Security-Auditing    | A service was installed                                      | Monitor installation of services that may be persistence vectors  |
| 4702     | Microsoft-Windows-Security-Auditing    | Scheduled task updated                                      | Track changes that could involve registry-based persistence       |
| 1100     | Microsoft-Windows-Eventlog             | Event log cleared                                           | Possible attacker cleanup after registry changes                  |
| 7045     | Microsoft-Windows-Service Control Manager | New service installed                                     | Detect new service installations, possible persistence mechanisms |
| 7040     | Microsoft-Windows-Service Control Manager | Service start type changed                               | Detect changes to service startup behavior                        |

## Windows Network Connections and Firewall Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                    |
|----------|----------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| 5156     | Microsoft-Windows-Security-Auditing    | The Windows Filtering Platform permitted a connection        | Monitor allowed inbound/outbound connections                      |
| 5157     | Microsoft-Windows-Security-Auditing    | The Windows Filtering Platform blocked a connection          | Detect blocked malicious connection attempts                      |
| 5031     | Microsoft-Windows-Windows Firewall With Advanced Security | The Windows Firewall service was stopped                  | Detect firewall service stoppage (potential tampering)           |
| 5032     | Microsoft-Windows-Windows Firewall With Advanced Security | The Windows Firewall service was started                  | Confirm firewall service startup                                  |
| 4946     | Microsoft-Windows-Security-Auditing    | A change has been made to Windows Firewall exception list     | Detect changes allowing exceptions (potential backdoors)         |
| 4947     | Microsoft-Windows-Security-Auditing    | A change has been made to Windows Firewall settings           | Monitor firewall configuration changes                           |
| 1102     | Microsoft-Windows-Eventlog             | The audit log was cleared                                     | Detect log clearing to hide network activities                   |

## Windows Group Policy Changes and Application Control
| Event ID | Provider                              | Description                                                    | Security Use Case                                                    |
|----------|----------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| 4739     | Microsoft-Windows-Security-Auditing    | Domain Policy was changed                                     | Detect unauthorized Group Policy modifications                    |
| 4713     | Microsoft-Windows-Security-Auditing    | Audit Policy Change                                           | Track changes to audit settings via Group Policy                  |
| 1129     | Microsoft-Windows-GroupPolicy           | Group Policy Object created or changed                        | Monitor GPO lifecycle events                                      |
| 1130     | Microsoft-Windows-GroupPolicy           | Group Policy Object deleted                                   | Detect removal of security policies                               |
| 1131     | Microsoft-Windows-GroupPolicy           | Group Policy processing failed                                | Alert on failures that could indicate tampering                  |
| 8005     | Microsoft-Windows-CodeIntegrity         | Code Integrity policy changed                                 | Detect changes to application whitelisting policies               |
| 8004     | Microsoft-Windows-CodeIntegrity         | Code Integrity violation                                     | Detect execution of code violating integrity policies             |
