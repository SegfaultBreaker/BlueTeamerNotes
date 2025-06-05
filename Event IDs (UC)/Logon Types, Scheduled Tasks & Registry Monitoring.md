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
