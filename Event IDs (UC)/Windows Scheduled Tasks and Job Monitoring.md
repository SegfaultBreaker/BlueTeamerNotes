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
