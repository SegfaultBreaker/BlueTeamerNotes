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
