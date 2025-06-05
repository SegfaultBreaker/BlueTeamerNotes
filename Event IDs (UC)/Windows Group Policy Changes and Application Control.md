## Windows Group Policy Changes and Application Control

| Event ID | Provider                              | Description                                                    | Security Use Case                                                    |
|----------|----------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| 4739     | Microsoft-Windows-Security-Auditing    | Domain Policy was changed                                     | Detect unauthorized Group Policy modifications                    |
| 4713     | Microsoft-Windows-Security-Auditing    | Audit Policy Change                                           | Track changes to audit settings via Group Policy                  |
| 1129     | Microsoft-Windows-GroupPolicy           | Group Policy Object created or changed                        | Monitor GPO lifecycle events                                      |
| 1130     | Microsoft-Windows-GroupPolicy           | Group Policy Object deleted                                   | Detect removal of security policies                               |
| 1131     | Microsoft-Windows-GroupPolicy           | Group Policy processing failed                                | Alert on failures that could indicate tampering                  |
| 8005     | Microsoft-Windows-CodeIntegrity         | Code Integrity policy changed                                 | Detect changes to application whitelisting policies               |
| 8004     | Microsoft-Windows-CodeIntegrity         | Code Integrity violation                                     | Detect execution of code violating integrity policies             |
