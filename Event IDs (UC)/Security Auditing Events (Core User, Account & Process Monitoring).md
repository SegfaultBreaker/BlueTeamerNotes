## Security Auditing Events (Core User, Account & Process Monitoring)

| Event ID | Provider                            | Description                                                  | Security Use Case                                         |
|----------|-----------------------------------|--------------------------------------------------------------|----------------------------------------------------------|
| 4624     | Microsoft-Windows-Security-Auditing | An account was successfully logged on                        | Track successful user logons                              |
| 4625     | Microsoft-Windows-Security-Auditing | An account failed to log on                                  | Detect brute force or unauthorized access attempts       |
| 4634     | Microsoft-Windows-Security-Auditing | An account was logged off                                    | Track user logoffs                                        |
| 4647     | Microsoft-Windows-Security-Auditing | User initiated logoff                                        | User session tracking                                    |
| 4648     | Microsoft-Windows-Security-Auditing | A logon was attempted using explicit credentials            | Detect lateral movement and credential misuse            |
| 4672     | Microsoft-Windows-Security-Auditing | Special privileges assigned to new logon                     | Detect privilege escalation                               |
| 4688     | Microsoft-Windows-Security-Auditing | A new process has been created                               | Monitor process creation                                  |
| 4689     | Microsoft-Windows-Security-Auditing | A process has exited                                        | Monitor process termination                               |
| 4697     | Microsoft-Windows-Security-Auditing | A service was installed                                     | Detect persistence via new services                       |
| 4698     | Microsoft-Windows-Security-Auditing | A scheduled task was created                                | Detect persistence via scheduled tasks                   |
| 4699     | Microsoft-Windows-Security-Auditing | A scheduled task was deleted                                | Detect task removal or cleanup attempts                   |
| 4700     | Microsoft-Windows-Security-Auditing | A scheduled task was enabled                                | Persistence detection                                    |
| 4701     | Microsoft-Windows-Security-Auditing | A scheduled task was disabled                               | Possible attacker cleanup                                 |
| 4720     | Microsoft-Windows-Security-Auditing | A user account was created                                  | Detect creation of new user accounts                      |
| 4722     | Microsoft-Windows-Security-Auditing | A user account was enabled                                  | Track account enable events                               |
| 4723     | Microsoft-Windows-Security-Auditing | An attempt was made to change an account’s password        | Detect password changes                                   |
| 4724     | Microsoft-Windows-Security-Auditing | An attempt was made to reset an account’s password         | Detect password resets                                   |
| 4725     | Microsoft-Windows-Security-Auditing | A user account was disabled                                 | Account disablement or lockout                            |
| 4726     | Microsoft-Windows-Security-Auditing | A user account was deleted                                  | Account removal, possible attacker cleanup               |
| 4732     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled local group       | Detect privilege escalation                              |
| 4733     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled local group   | Group membership changes                                 |
| 4740     | Microsoft-Windows-Security-Auditing | A user account was locked out                               | Detect brute force lockouts                              |
| 4767     | Microsoft-Windows-Security-Auditing | A user account was unlocked                                | Unlock event tracking                                    |
| 4768     | Microsoft-Windows-Security-Auditing | A Kerberos authentication ticket (TGT) was requested      | Track Kerberos authentications                           |
| 4769     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was requested                    | Monitor service authentications                          |
| 4771     | Microsoft-Windows-Security-Auditing | Kerberos pre-authentication failed                         | Detect failed Kerberos auth attempts                     |
| 4776     | Microsoft-Windows-Security-Auditing | The domain controller attempted to validate credentials    | Domain authentication attempts                           |
| 4781     | Microsoft-Windows-Security-Auditing | The name of an account was changed                         | Detect account renaming                                  |
| 4794     | Microsoft-Windows-Security-Auditing | An attempt was made to set the Directory Services Restore Mode password | Possible attack or recovery attempts            |
| 4800     | Microsoft-Windows-Security-Auditing | The workstation was locked                                 | User activity tracking                                  |
| 4801     | Microsoft-Windows-Security-Auditing | The workstation was unlocked                               | User activity tracking                                  |
| 4902     | Microsoft-Windows-Security-Auditing | The Per-user audit policy table was created                | Audit policy changes                                    |
| 4904     | Microsoft-Windows-Security-Auditing | An attempt was made to register a security event source   | Detect attempts to tamper with event logs                |
| 4905     | Microsoft-Windows-Security-Auditing | An attempt was made to unregister a security event source | Detect log tampering                                    |
| 4906     | Microsoft-Windows-Security-Auditing | The Windows Firewall settings were changed                | Detect firewall rule changes                             |
| 4946     | Microsoft-Windows-Security-Auditing | A change has been made to Windows Firewall exception list | Firewall exception modifications                         |
| 4956     | Microsoft-Windows-Security-Auditing | A rule was added to the Windows Firewall exception list   | Firewall rule additions                                 |
| 4957     | Microsoft-Windows-Security-Auditing | A rule was deleted from the Windows Firewall exception list | Firewall rule deletions                                |
| 4960     | Microsoft-Windows-Security-Auditing | IPsec dropped a packet due to failed negotiation           | Possible blocked malicious traffic                       |
| 1102     | Microsoft-Windows-Security-Auditing | The audit log was cleared                                  | Possible attacker cleanup                                |
