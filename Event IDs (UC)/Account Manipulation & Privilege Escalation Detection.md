## Account Manipulation & Privilege Escalation Detection

| Event ID | Provider                              | Description                                                       | Security Use Case                                                    |
|----------|----------------------------------------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| 4720     | Microsoft-Windows-Security-Auditing    | A user account was created                                        | Rogue account creation for persistence                              |
| 4722     | Microsoft-Windows-Security-Auditing    | A user account was enabled                                        | Reactivation of a dormant or backdoor account                       |
| 4723     | Microsoft-Windows-Security-Auditing    | A user attempted to change own password                           | Account takeover detection                                           |
| 4724     | Microsoft-Windows-Security-Auditing    | Attempt to reset another user’s password                          | Lateral movement or privilege escalation attempt                     |
| 4725     | Microsoft-Windows-Security-Auditing    | User account disabled                                             | Deactivation of legitimate users (DOS or cover-up)                  |
| 4726     | Microsoft-Windows-Security-Auditing    | User account deleted                                              | Hide traces of malicious accounts                                   |
| 4731     | Microsoft-Windows-Security-Auditing    | A security-enabled local group was created                        | Persistence through group abuse                                     |
| 4732     | Microsoft-Windows-Security-Auditing    | A member was added to a security-enabled local group              | Escalation (e.g., user added to Administrators group)               |
| 4733     | Microsoft-Windows-Security-Auditing    | A member was removed from a security-enabled local group          | Cleanup of escalation or lateral movement                           |
| 4735     | Microsoft-Windows-Security-Auditing    | Security-enabled local group modified                             | Group tampering for stealth or persistence                          |
| 4737     | Microsoft-Windows-Security-Auditing    | Security-enabled global group modified                            | Domain-level escalation detection                                   |
| 4756     | Microsoft-Windows-Security-Auditing    | Security-enabled universal group created                          | High-level domain group creation                                    |
| 4757     | Microsoft-Windows-Security-Auditing    | Member added to universal group                                   | Domain-wide permission escalation                                   |
| 4758     | Microsoft-Windows-Security-Auditing    | Member removed from universal group                               | Cleanup or stealthy privilege removal                               |
| 4670     | Microsoft-Windows-Security-Auditing    | Permissions on an object were changed                             | Detect sensitive file/folder ACL changes                            |
| 4671     | Microsoft-Windows-Security-Auditing    | Application attempted to access a protected object                | Privilege escalation attempt                                        |
| 4964     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                          | Detection of logon with high privileges                             |
| 4902     | Microsoft-Windows-Security-Auditing    | Audit policy was changed                                          | Potential log tampering / stealth                                    |
| 4612     | Microsoft-Windows-Security-Auditing    | Internal security authority (LSASS) initialization                | Monitoring changes to authentication mechanisms                     |
