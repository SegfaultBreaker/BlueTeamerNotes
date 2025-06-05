## Command & Control (C2) Communications Detection

| Event ID | Provider                              | Description                                                      | Security Use Case                                                   |
|----------|----------------------------------------|------------------------------------------------------------------|----------------------------------------------------------------------|
| 3        | Microsoft-Windows-Sysmon               | Network connection                                               | Detect callback IPs or known C2 ports (e.g., 4444, 8080, 53)         |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                                 | Identify C2 agents (e.g., `powershell`, `mshta`, `rundll32`)         |
| 8        | Microsoft-Windows-Sysmon               | CreateRemoteThread                                               | Used in Cobalt Strike/Metasploit for injection                      |
| 7        | Microsoft-Windows-Sysmon               | Image loaded                                                     | Detect malicious DLLs used by C2 agents                             |
| 10       | Microsoft-Windows-Sysmon               | Process accessed another process                                 | Common in malware staging and injection                             |
| 5145     | Microsoft-Windows-Security-Auditing    | Network share accessed                                           | Peer-to-peer or lateral movement between agents                     |
| 5156     | Microsoft-Windows-Security-Auditing    | Allowed network connection                                       | Spot connections to C2 servers or beacon IPs                        |
| 5158     | Microsoft-Windows-Security-Auditing    | Low-level outbound connection                                    | Monitor stealthy outbound traffic                                   |
| 5059     | Microsoft-Windows-WMI-Activity         | WMI consumer binding                                             | Persistence / lateral tool used by agents                           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                        | Beacon domains, FastFlux, DGAs (e.g., `.xyz`, `.top`, etc.)         |
| 10000    | Microsoft-Windows-TCPIP                | Outbound TCP connection                                          | Catch outbound C2 to nonstandard ports                              |
| 4688     | Microsoft-Windows-Security-Auditing    | Process creation                                                 | Initial launch of agent, C2 loader (e.g., `powershell -enc`)         |
| 4104     | Microsoft-Windows-PowerShell/Operational | Script block logging                                           | Detect encoded or obfuscated C2 script payloads                     |
| 4103     | Microsoft-Windows-PowerShell/Operational | Command invocation                                              | Logs each PowerShell command                                         |
| 3002     | Microsoft-Windows-CodeIntegrity        | Driver signature check failed                                    | Malware driver load (e.g., rootkit C2 channels)                     |
| 7045     | Microsoft-Windows-Service Control Manager | New service installed                                          | C2 agents installed as services                                     |
