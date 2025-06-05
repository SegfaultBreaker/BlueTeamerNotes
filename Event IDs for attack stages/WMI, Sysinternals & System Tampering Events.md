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
