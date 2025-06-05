## Active Directory & Group Policy Related Events

| Event ID | Provider                            | Description                                                     | Security Use Case                                             |
|----------|-----------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| 5136     | Microsoft-Windows-Security-Auditing | A directory service object was modified                         | Detect AD object changes (users, computers, groups)          |
| 5137     | Microsoft-Windows-Security-Auditing | A directory service object was created                          | Track creation of AD objects                                  |
| 5138     | Microsoft-Windows-Security-Auditing | A directory service object was undeleted                        | Detect object recovery                                        |
| 5139     | Microsoft-Windows-Security-Auditing | A directory service object was moved                            | Track AD object moves                                        |
| 5141     | Microsoft-Windows-Security-Auditing | A directory service object was deleted                          | Detect AD object deletions                                    |
| 4742     | Microsoft-Windows-Security-Auditing | A computer account was changed                                  | Detect changes to computer accounts                           |
| 4743     | Microsoft-Windows-Security-Auditing | A computer account was deleted                                  | Detect deletion of computer accounts                          |
| 4744     | Microsoft-Windows-Security-Auditing | A security-disabled local group was created                     | Track creation of local groups                                |
| 4745     | Microsoft-Windows-Security-Auditing | A security-disabled local group was changed                     | Track changes to local groups                                 |
| 4746     | Microsoft-Windows-Security-Auditing | A security-disabled local group was deleted                     | Track deletion of local groups                                |
| 4747     | Microsoft-Windows-Security-Auditing | A security-enabled global group was created                     | Detect new global groups                                      |
| 4748     | Microsoft-Windows-Security-Auditing | A security-enabled global group was changed                     | Track global group changes                                    |
| 4749     | Microsoft-Windows-Security-Auditing | A security-enabled global group was deleted                     | Track deletion of global groups                               |
| 4750     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was created                  | Detect new universal groups                                   |
| 4751     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was changed                  | Track universal group changes                                 |
| 4752     | Microsoft-Windows-Security-Auditing | A security-enabled universal group was deleted                  | Track deletion of universal groups                            |
| 4753     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled global group           | Privilege escalation detection                               |
| 4754     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled global group       | Group membership removal                                     |
| 4755     | Microsoft-Windows-Security-Auditing | A member was added to a security-enabled universal group        | Group membership changes                                     |
| 4756     | Microsoft-Windows-Security-Auditing | A member was removed from a security-enabled universal group    | Group membership changes                                     |
| 4757     | Microsoft-Windows-Security-Auditing | A member was added to a security-disabled local group           | Group membership changes                                     |
| 4758     | Microsoft-Windows-Security-Auditing | A member was removed from a security-disabled local group       | Group membership changes                                     |
| 4761     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket request failed                        | Authentication failure detection                             |
| 4762     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was renewed                            | Ticket renewal tracking                                     |
| 4763     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was renewed after forwardable         | Advanced ticket tracking                                     |
| 4764     | Microsoft-Windows-Security-Auditing | A Kerberos service ticket was requested with a different name   | Ticket misuse detection                                     |
| 4798     | Microsoft-Windows-Security-Auditing | A user's local group membership was enumerated                  | Detect reconnaissance of group memberships                  |
| 4799     | Microsoft-Windows-Security-Auditing | A security-enabled local group membership was enumerated        | Detect reconnaissance of privileged groups                  |
| 4864     | Microsoft-Windows-Security-Auditing | A basic application group was created                            | Group creation monitoring                                   |
| 4865     | Microsoft-Windows-Security-Auditing | A basic application group was changed                            | Group modification detection                                |
| 4866     | Microsoft-Windows-Security-Auditing | A basic application group was deleted                            | Group deletion monitoring                                   |
| 4907     | Microsoft-Windows-Security-Auditing | Auditing settings on object were changed                         | Audit policy monitoring                                     |
| 4739     | Microsoft-Windows-Security-Auditing | Domain Policy was changed                                        | Detect Group Policy changes                                 |
| 1644     | Microsoft-Windows-GroupPolicy       | Group Policy settings were processed                             | Monitor Group Policy application                            |

