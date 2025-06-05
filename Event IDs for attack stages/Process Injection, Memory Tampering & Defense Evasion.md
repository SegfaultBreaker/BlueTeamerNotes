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
