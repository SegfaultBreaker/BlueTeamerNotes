## User Account and Privilege Management Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                     |
|----------|----------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------|
| 4720     | Microsoft-Windows-Security-Auditing    | User account created                                         | Detect unauthorized user creation                                   |
| 4722     | Microsoft-Windows-Security-Auditing    | User account enabled                                       | Track activation of dormant accounts                                |
| 4723     | Microsoft-Windows-Security-Auditing    | User account password change attempted                     | Detect password change attempts                                     |
| 4724     | Microsoft-Windows-Security-Auditing    | Password reset attempted                                   | Monitor reset of user passwords                                     |
| 4725     | Microsoft-Windows-Security-Auditing    | User account disabled                                      | Detect disabling of user accounts                                   |
| 4726     | Microsoft-Windows-Security-Auditing    | User account deleted                                      | Track account removal                                              |
| 4732     | Microsoft-Windows-Security-Auditing    | Member added to a security-enabled local group            | Detect privilege escalation via group membership                   |
| 4733     | Microsoft-Windows-Security-Auditing    | Member removed from a security-enabled local group        | Monitor privilege revocation                                       |
| 4672     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                  | Identify privileged logons                                         |
| 4768     | Microsoft-Windows-Security-Auditing    | Kerberos authentication ticket requested                  | Track authentication activity                                      |
| 4769     | Microsoft-Windows-Security-Auditing    | Kerberos service ticket requested                         | Monitor service ticket requests                                    |
| 4771     | Microsoft-Windows-Security-Auditing    | Kerberos pre-authentication failed                        | Detect possible brute force or credential attacks                  |
| 4776     | Microsoft-Windows-Security-Auditing    | NTLM authentication attempted                             | Track NTLM auth, often used in lateral movement                    |
