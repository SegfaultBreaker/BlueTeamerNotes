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
