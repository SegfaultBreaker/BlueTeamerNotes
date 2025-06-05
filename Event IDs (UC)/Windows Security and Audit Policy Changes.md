## Windows Security and Audit Policy Changes

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 4719     | Microsoft-Windows-Security-Auditing    | System audit policy was changed                              | Detect changes in audit settings that reduce visibility            |
| 4902     | Microsoft-Windows-Security-Auditing    | The audit policy (SACL) on an object was changed             | Monitor SACL tampering on sensitive objects                        |
| 4904     | Microsoft-Windows-Security-Auditing    | Windows Firewall was changed                                 | Detect firewall policy modifications                               |
| 4905     | Microsoft-Windows-Security-Auditing    | Windows Firewall policy was changed                          | Monitor detailed firewall policy changes                          |
| 4715     | Microsoft-Windows-Security-Auditing    | Audit policy change attempted                               | Track attempts to alter audit policies                             |
| 1102     | Microsoft-Windows-Eventlog             | The audit log was cleared                                   | Detect log clearing often used to cover tracks                    |
| 4616     | Microsoft-Windows-Security-Auditing    | System time was changed                                     | Detect time tampering to obfuscate event timelines                |
| 4704     | Microsoft-Windows-Security-Auditing    | User right was assigned                                     | Detect assignment of sensitive user rights                        |
| 4705     | Microsoft-Windows-Security-Auditing    | User right was removed                                     | Monitor removal of user rights                                    |
