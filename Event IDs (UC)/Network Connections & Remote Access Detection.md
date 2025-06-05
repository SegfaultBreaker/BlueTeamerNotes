## Network Connections & Remote Access Detection

| Event ID | Provider                              | Description                                                     | Security Use Case                                                  |
|----------|----------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------------|
| 4624     | Microsoft-Windows-Security-Auditing    | Successful logon                                               | Detect remote logons (Type 3, Type 10 = network, RDP)               |
| 4625     | Microsoft-Windows-Security-Auditing    | Failed logon                                                   | Detect brute-force or failed remote access                          |
| 4648     | Microsoft-Windows-Security-Auditing    | Logon with explicit credentials                                | Detect pass-the-hash/ticket/credential use                         |
| 4672     | Microsoft-Windows-Security-Auditing    | Special privileges assigned to new logon                       | High-privileged session detection                                   |
| 4778     | Microsoft-Windows-Security-Auditing    | RDP session reconnected                                        | RDP tracking                                                        |
| 4779     | Microsoft-Windows-Security-Auditing    | RDP session disconnected                                       | RDP tracking                                                        |
| 5140     | Microsoft-Windows-Security-Auditing    | Network share object accessed                                  | Detect access to administrative or sensitive shares                 |
| 5145     | Microsoft-Windows-Security-Auditing    | Detailed share access attempt                                  | Forensic detail on share access attempts                            |
| 5156     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: Allowed network connection         | Track allowed outbound connections                                  |
| 5158     | Microsoft-Windows-Security-Auditing    | WFP: connection permit                                          | Map lateral movement, C2 beacons, etc.                              |
| 5152     | Microsoft-Windows-Security-Auditing    | Windows Filtering Platform: Blocked network connection         | Detect blocked malicious traffic attempts                           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                      | Track domain name resolution — useful for identifying C2 domains    |
| 6013     | Microsoft-Windows-TerminalServices-LocalSessionManager | User session duration                             | RDP session auditing                                                |
| 1024     | Microsoft-Windows-TLS-SSL              | TLS handshake initiated                                        | Detect encrypted communication initiation (can be C2)              |
| 10000    | Microsoft-Windows-TCPIP                | Outbound connection initiated                                  | See which IPs/ports are contacted                                  |
| 5157     | Microsoft-Windows-Security-Auditing    | Packet dropped                                                 | Firewall dropped malicious or unauthorized connection              |
| 5379     | Microsoft-Windows-Security-Auditing    | Credential validation via NPS                                  | VPN, wireless auth — useful for remote access forensics             |
| 4647     | Microsoft-Windows-Security-Auditing    | User initiated logoff                                          | Track session terminations                                          |
| 4769     | Microsoft-Windows-Security-Auditing    | Kerberos service ticket requested                              | Monitor service access and lateral movement                         |
| 4771     | Microsoft-Windows-Security-Auditing    | Kerberos pre-auth failed                                       | Password guessing, replay, or time-skew attacks                     |
| 1149     | Microsoft-Windows-Security-Auditing    | RDP connection was established                                 | RDP connection successfull / established                            |
