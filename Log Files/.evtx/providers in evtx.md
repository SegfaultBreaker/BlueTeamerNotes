🛡️ Security & Authentication

| Provider                                | Description                                  | Security Use Case                                           |
|-----------------------------------------|----------------------------------------------|-------------------------------------------------------------|
| Microsoft-Windows-Security-Auditing     | Core Windows security audit log              | Logon tracking, privilege use, policy changes               |
| Microsoft-Windows-Winlogon              | Manages user logon/logoff                    | Tracks interactive sessions and shell startups              |
| Microsoft-Windows-User Profiles Service | Handles user profile load/unload             | Useful for user session and RDP activity                    |
| Microsoft-Windows-BitLocker-API         | Disk encryption logs                         | Detects encryption use, tampering, or access issues         |
| Microsoft-Windows-Privacy-Auditing      | Audits privacy-related settings              | Tracks modifications to sensitive privacy settings          |
| Microsoft-Windows-User Device Registration | Device registration (e.g. Azure AD join)   | Detects hybrid or cloud onboarding                          |
| Microsoft-Windows-WebAuthN              | Web-based (FIDO2) login logging              | Monitors hardware-backed authentication                     |
| Microsoft-Windows-SmartScreen | Windows event provider that logs SmartScreen activities and alerts related to application and file reputation filtering | Monitoring and auditing SmartScreen actions: blocking files, warning on unrecognized apps, and analyzing detected threats |

🖥️ System & Kernel Events

| Provider                            | Description                          | Security Use Case                                         |
|-------------------------------------|--------------------------------------|-----------------------------------------------------------|
| Microsoft-Windows-Kernel-General    | Boot/shutdown/system time events     | Establish system baseline; detect boot tampering         |
| Microsoft-Windows-Kernel-Power      | Power state transitions              | Detect unexpected shutdowns or power loss                |
| Microsoft-Windows-Kernel-EventTracing | ETW session tracking               | Can reveal stealth attacker instrumentation              |
| Microsoft-Windows-Kernel-Boot       | System boot data                     | Identify anomalies in the boot process                   |
| Microsoft-Windows-Kernel-WHEA       | Hardware error logging               | Hardware tampering or degradation                        |
| Microsoft-Windows-HAL               | Hardware abstraction layer           | Low-level power/driver related diagnostics               |

⚙️ Configuration & Services

| Provider                            | Description                             | Security Use Case                                           |
|-------------------------------------|-----------------------------------------|-------------------------------------------------------------|
| Service Control Manager             | Manages services                        | Detect creation of malicious services                       |
| Microsoft-Windows-TaskScheduler     | Task scheduler activity                 | Tracks scheduled tasks often used for persistence           |
| Microsoft-Windows-GroupPolicy       | Group Policy processing                 | Indicates policy tampering by attackers                     |
| Microsoft-Windows-Servicing         | OS and feature update tracking          | Detect unauthorized upgrades or modifications               |
| Microsoft-Windows-DHCP-Client       | DHCP IP assignment                      | Detect IP/machine movement                                  |
| Microsoft-Windows-WinRM             | Windows Remote Management               | Remote access or PowerShell remoting                        |

💡 Application Execution & Monitoring

| Provider                                | Description                              | Security Use Case                                            |
|-----------------------------------------|------------------------------------------|--------------------------------------------------------------|
| Microsoft-Windows-PowerShell            | PowerShell command execution             | Detects script block usage (e.g., 4104 events)               |
| Microsoft-Windows-AppModel-Runtime      | UWP app execution                        | Tracks app container activity                                |
| Microsoft-Windows-WMI-Activity          | WMI usage monitoring                     | Common for attacker persistence/lateral movement             |
| Microsoft-Windows-Eventlog              | Event log service                        | Detects log clearing or corruption attempts                  |
| Microsoft-Windows-DistributedCOM        | DCOM interactions                        | Lateral movement or remote code execution                    |

📦 Installation & Updates

| Provider                                | Description                                | Security Use Case                                           |
|-----------------------------------------|--------------------------------------------|-------------------------------------------------------------|
| MsiInstaller                            | MSI installation logs                      | Detects installs of unauthorized software                   |
| Microsoft-Windows-WindowsUpdateClient   | Windows Update client activity             | Tracks update behavior, patch gaps                         |
| Microsoft-Windows-AppXDeployment        | UWP app installations                      | Detects side-loaded or malicious packaged apps             |

📡 Network & Communication

| Provider                                | Description                             | Security Use Case                                            |
|-----------------------------------------|-----------------------------------------|--------------------------------------------------------------|
| Microsoft-Windows-DNS-Client            | DNS query events                        | Detects C2 or suspicious domain resolutions                 |
| Microsoft-Windows-NetworkProfile        | Network environment tracking            | Detects new or unauthorized network connections             |
| Microsoft-Windows-WinINet-Config        | Internet config settings                | Proxy manipulation, malicious routing                       |
| Microsoft-Windows-HttpEvent             | HTTP activity via kernel logging        | Web exploit or exfiltration vector tracing                  |

☁️ Cloud & Telemetry

| Provider                                | Description                                   | Security Use Case                                             |
|-----------------------------------------|-----------------------------------------------|----------------------------------------------------------------|
| Microsoft-Windows-AAD                   | Azure Active Directory client logs            | Hybrid domain joins and conditional access monitoring         |
| Microsoft-Windows-UniversalTelemetryClient | Windows telemetry service                   | Monitoring for abnormal outbound telemetry                    |
| Microsoft-Client-Licensing-Platform     | License validation & product activation       | Sometimes abused for persistence or evasion                   |

💥 Errors, Crashes, and Recovery

| Provider                   | Description                        | Security Use Case                                  |
|----------------------------|------------------------------------|----------------------------------------------------|
| Application Error          | App crash logging                  | Malware crashes or exploitation attempts           |
| Windows Error Reporting    | Crash dump reporting               | Behavioral analysis or crash-loop detection        |
| ESENT                      | Extensible Storage Engine logging  | Malware using internal Windows databases           |

🧪 Virtualization & Sandboxes (VM-related)

| Provider               | Description                          | Security Use Case                                |
|------------------------|--------------------------------------|--------------------------------------------------|
| VMTools                | VMware Tools                         | Indicates presence of virtualized environment    |
| VMUpgradeHelper        | VMware upgrade tool logging          | Used in VM lifecycle or forensic correlation     |
| vmci                   | VMware Communication Interface       | Network bridging or host communication detection |


