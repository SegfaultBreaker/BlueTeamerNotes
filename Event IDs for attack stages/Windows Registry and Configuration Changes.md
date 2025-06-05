## Windows Registry and Configuration Changes

| Event ID | Provider                              | Description                                                   | Security Use Case                                                    |
|----------|----------------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------|
| 4657     | Microsoft-Windows-Security-Auditing    | Registry value modified                                      | Detect changes to critical registry keys                           |
| 4697     | Microsoft-Windows-Security-Auditing    | A service was installed                                      | Monitor installation of services that may be persistence vectors  |
| 4702     | Microsoft-Windows-Security-Auditing    | Scheduled task updated                                      | Track changes that could involve registry-based persistence       |
| 1100     | Microsoft-Windows-Eventlog             | Event log cleared                                           | Possible attacker cleanup after registry changes                  |
| 7045     | Microsoft-Windows-Service Control Manager | New service installed                                     | Detect new service installations, possible persistence mechanisms |
| 7040     | Microsoft-Windows-Service Control Manager | Service start type changed                               | Detect changes to service startup behavior                        |
