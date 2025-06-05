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
