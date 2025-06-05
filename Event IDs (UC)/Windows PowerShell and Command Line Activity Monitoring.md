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
