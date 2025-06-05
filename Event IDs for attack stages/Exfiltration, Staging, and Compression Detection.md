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
