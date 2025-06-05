## Application Whitelisting and Code Integrity Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 8004     | Microsoft-Windows-CodeIntegrity        | Code integrity violation                                      | Detect unsigned or tampered binaries execution                      |
| 8003     | Microsoft-Windows-CodeIntegrity        | Code integrity check success                                  | Confirm allowed binaries                                            |
| 8005     | Microsoft-Windows-CodeIntegrity        | Code integrity policy change                                  | Detect changes to whitelisting policies                             |
| 5007     | Microsoft-Windows-Windows Defender     | Configuration change                                         | Spot tampering of Defender/AppLocker settings                       |
| 8000     | Microsoft-Windows-AppLocker             | Executable blocked                                           | Detect blocked application runs                                    |
| 8001     | Microsoft-Windows-AppLocker             | Executable allowed                                           | Confirm allowed application runs                                   |
| 8020     | Microsoft-Windows-AppLocker             | DLL blocked                                                | Detect blocked DLL loads                                           |
| 8021     | Microsoft-Windows-AppLocker             | DLL allowed                                                | Confirm allowed DLL loads                                          |
| 8030     | Microsoft-Windows-AppLocker             | Script blocked                                            | Detect blocked script executions                                  |
| 8031     | Microsoft-Windows-AppLocker             | Script allowed                                            | Confirm allowed script executions                                 |
