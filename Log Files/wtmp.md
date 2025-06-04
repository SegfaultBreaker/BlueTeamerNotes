# Reading a wtpmp file from unix systems

What is the wtpmp file ? 

The wtmp file serves as a system log that records all login and logout activities. This file is in binary format and is usually found at /var/log/wtmp. To view its contents, you can use the last command, which displays a historical record of user sessions, including logins, logouts, system restarts, and changes in runlevel.

Information Contained in wtmp
Because wtmp is a binary file, it cannot be read like plain text logs such as auth.log. However, tools like last interpret and present the data in a human-readable format, including:

- Username: Identifies the user who logged in or out.
- Terminal: Specifies the terminal (TTY) used for the session. Remote sessions often indicate SSH or Telnet details.
- IP Address or Hostname: For remote sessions, this shows the originating IP address or hostname.
- Login Time: The date and time when the session began.
- Logout Time: When the session ended or the user logged out.
- Session Duration: The total length of the session.

Below is a sample output of the last command:

SegfaultBreaker pts/0 10.1.1.1 Sat April 9 09:25 - 10:25 (01:00).

The user Segfaulbreaker was logged in for 1h. 


## Important

It is important to understand that problems may arise when using standard tools like last or utmpdump if the CPU architecture of the forensic investigator’s machine differs from that of the system where the wtmp file was originally created. To address this issue, use a tool called utmp.py (https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5).

## reading utmp.py inputs

![image](https://github.com/user-attachments/assets/ba18a964-8e5e-4590-9b9c-aba70142505e)

Took from the website : https://www.kazamiya.net/en/bulk_extractor-rec/utmp

| Field      | Description                                                                                           |
|------------|-------------------------------------------------------------------------------------------------------|
| **Type**   | Specifies the type of record, such as user login, logout, system boot, or shutdown event.            |
| **PID**    | The Process ID associated with the event.                                                             |
| **Line**   | The terminal line where the session occurred. `tty` refers to a physical terminal (e.g., local console), while `pts` refers to a pseudo-terminal used for remote or virtual sessions (e.g., SSH). |
| **ID**     | A short identifier linked to the terminal line.                                                       |
| **User**   | The username involved in the event.                                                                   |
| **Host**   | The hostname or IP address from which the user accessed the system, if applicable.                   |
| **Exit**   | The exit status of the session or process.                                                            |
| **Session**| The session identifier.                                                                               |
| **sec**    | The event timestamp in seconds (based on your system's timezone, not the source system's).           |
| **usec**   | The microsecond part of the timestamp related to the login/logout event.                              |
| **Addr**   | Additional address info, such as an IP address for remote connections.                                |




# Usefull information that can be retrieved with this tool.



## wtmp

"USER"  "3120"  "pts/0"  "ts/1"  "john"  "203.0.113.45"  "0"  "0"  "2024/05/28 10:14:22"  "312456"  "203.0.113.45"

| Field             | Value             | Description                                               |
|------------------|-------------------|-----------------------------------------------------------|
| **Type**         | `"USER"`          | Type of event (user login)                                |
| **PID**          | `"3120"`          | Process ID of the session                                 |
| **Line**         | `"pts/0"`         | Terminal line used (pseudo-terminal)                      |
| **ID**           | `"ts/1"`          | Line ID (used for internal session tracking)              |
| **User**         | `"john"`          | Username who logged in                                    |
| **Host**         | `"203.0.113.45"`  | Remote IP address of the user                             |
| **Exit Code**    | `"0"`             | Exit status (0 = successful)                              |
| **Session**      | `"0"`             | Session ID (can vary depending on the system)             |
| **Login Time**   | `"2024/05/28 10:14:22"` | Timestamp of login                               |
| **Microseconds** | `"312456"`        | Microsecond part of the login timestamp                   |
| **Addr**         | `"203.0.113.45"`  | Redundant IP field (used in some UTMP/WTMP tools)         |
