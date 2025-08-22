# 🕵️‍♀️ Wireshark Threat Hunting & Network Analysis Cheat Sheet

A practical reference to hunt suspicious/malicious activity in packet captures.
Each entry includes:

**🎯 Filter**

**🔍 What it does**

**🚨 Why it matters**

**🗡 MITRE ATT&CK mapping**

**🧑‍💻 How to investigate like a SOC analyst**

⚡ Tip: Pair filters with **Follow TCP/UDP Stream, Statistics → Endpoints/Conversations,** and **Export Objects (HTTP/SMB/FTP)** to quickly extract evidence.

---

# 📑 Index – Wireshark Threat Hunting & Network Analysis Cheat Sheet

1. [📘 Beginner Filters](#📘-beginner-filters)  
2. [📗 Intermediate Filters](#📗-intermediate-filters)  
3. [📙 Advanced Filters](#📙-advanced-filters)  
4. [1️⃣ General Scoping & Baseline](#1️⃣-general-scoping--baseline)  
5. [2️⃣ Suspicious Indicators (Quick Wins)](#2️⃣-suspicious-indicators-quick-wins)  
6. [3️⃣ Credentials & Sensitive Data Exposure](#3️⃣-credentials--sensitive-data-exposure)  
7. [4️⃣ Lateral Movement & Internal Abuse](#4️⃣-lateral-movement--internal-abuse)  
8. [5️⃣ Malware Delivery & Tooling](#5️⃣-malware-delivery--tooling)  
9. [6️⃣ Command & Control (C2) & Beaconing](#6️⃣-command--control-c2--beaconing)  
10. [7️⃣ Data Exfiltration Patterns](#7️⃣-data-exfiltration-patterns)  
11. [8️⃣ Phishing & Initial Access](#8️⃣-phishing--initial-access)  
12. [9️⃣ Protocol Abuse & Exploitation](#9️⃣-protocol-abuse--exploitation)  
13. [🔟 Handy Field Extractors](#🔟-handy-field-extractors)

---

## 📘 Beginner Filters


| Filter                  | Description                                   |
| ----------------------- | --------------------------------------------- |
| `ip.src == 192.168.1.1` | Show traffic **from** a specific source IP    |
| `ip.dst == 192.168.1.1` | Show traffic **to** a specific destination IP |
| `ip.addr == 10.0.0.5`   | Show **all traffic to/from** a host           |
| `tcp.port == 80`        | Display HTTP traffic                          |
| `udp.port == 53`        | Display DNS traffic                           |
| `icmp`                  | Show ICMP (ping) packets                      |
| `http`                  | Show all HTTP packets                         |
| `dns`                   | Show all DNS packets                          |
| `arp`                   | Show ARP packets (who has / is at)            |


## 📗 Intermediate Filters

| Filter                                     | Description                                 |
| ------------------------------------------ | ------------------------------------------- |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Show **SYN packets only** (new connections) |
| `tcp.flags.fin == 1`                       | Show **TCP FIN packets** (connection close) |
| `tcp.flags.reset == 1`                     | Show **TCP RST packets** (reset)            |
| `tcp.analysis.retransmission`              | Show TCP retransmissions                    |
| `tcp.analysis.flags`                       | Display TCP errors/warnings                 |
| `http.request.method == "GET"`             | Show HTTP GET requests                      |
| `http.request.method == "POST"`            | Show HTTP POST requests                     |
| `http.host == "example.com"`               | Show HTTP traffic to a specific domain      |
| `frame contains "password"`                | Find packets containing "password"          |
| `tcp contains "admin"`                     | Find TCP data with "admin" keyword          |
| `ftp`                                      | Show FTP traffic                            |
| `smtp`                                     | Show SMTP (email) traffic                   |


## 📙 Advanced Filters

| Filter                     | Description                                                   |
| -------------------------- | ------------------------------------------------------------- |
| `ip.geoip.country == "US"` | Show packets from the **United States** (if GeoIP is enabled) |
| `tcp.analysis.window_full` | Display packets where TCP receive window is full              |
| `tcp.analysis.zero_window` | Show TCP zero window issues                                   |
| `!(arp or icmp or dns)`    | Show all traffic **except ARP, ICMP, and DNS**                |
| `tcp.stream eq 5`          | Follow a specific **TCP stream**                              |
| `frame.time_delta > 1`     | Show packets where time between frames > 1s                   |
| `tcp.len > 0`              | Show only packets with actual **TCP data**, not empty ACKs    |

---


## 1️⃣ General Scoping & Baseline

| Filter                                 | What it does          | Why it matters 🚨           | MITRE ATT\&CK                   | Investigate like a SOC analyst                                             |
| -------------------------------------- | --------------------- | --------------------------- | ------------------------------- | -------------------------------------------------------------------------- |
| `ip.addr == 192.168.1.10`              | Focus on a host       | Narrow to victim/suspect    | —                               | Endpoints → sort by Bytes; Conversations → top talkers; resolve MAC/vendor |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | TCP SYN (no ACK)      | Port scanning / recon       | T1046 Network Service Discovery | Conversations (TCP) → many dest ports? Same src? Time plot for bursts      |
| `icmp`                                 | ICMP echo/traceroute  | Host discovery, mapping     | T1046, T1071.004                | Check unusual freq/size; validate internal policy                          |
| `dns`                                  | DNS queries/responses | Domain intel, C2 hints      | T1071.004                       | Follow UDP stream; look at `dns.qry.name`, TTL, NXDOMAIN                   |
| `http`                                 | Cleartext web         | Injects, downloads, beacons | T1071.001                       | Check methods, URIs, User-Agent, Hosts; Export Objects → HTTP              |
| `tls`                                  | TLS sessions          | Encrypted C2/beacons        | T1071.001                       | Inspect SNI (`tls.handshake.extensions_server_name`), JA3/JA3S             |


## 2️⃣ Suspicious Indicators (Quick Wins)

| Filter                                                         | What it does           | Why it matters 🚨                              | MITRE ATT\&CK    | Investigate                                 |
| -------------------------------------------------------------- | ---------------------- | ---------------------------------------------- | ---------------- | ------------------------------------------- |
| `tcp.flags.reset==1`                                           | TCP RST floods         | Failed conns → scans, brute force, unstable C2 | T1046, T1110     | Plot over time; correlate RSTs with src/dst |
| `dns && frame.len > 200`                                       | Oversized DNS          | DNS tunneling / exfil                          | T1071.004, T1041 | Extract query names; look for base64 labels |
| `udp.port==53 && frame.len > 300`                              | Big DNS over UDP       | Aggressive tunneling                           | T1071.004, T1572 | Check QPS spikes; NXDOMAIN ratio            |
| `http.user_agent contains "curl" or "wget"`                    | Non-browser UA         | Scripting, malware tools                       | —                | Look for automation in requests             |
| `tcp.analysis.retransmission`                                  | Retransmissions        | DoS, C2 jitter                                 | T1498            | Compare RTT, packet loss per flow           |
| `frame.len > 1500 && ip.dst !in {10/8, 172.16/12, 192.168/16}` | Large external packets | Data exfil                                     | T1041, T1048     | Validate ASN/geo; align with file access    |

## 3️⃣ Credentials & Sensitive Data Exposure

| Filter                                    | What it does           | Why it matters 🚨        | MITRE ATT\&CK    | Investigate                              |
| ----------------------------------------- | ---------------------- | ------------------------ | ---------------- | ---------------------------------------- |
| `ftp.request.command == "USER" or "PASS"` | FTP creds in cleartext | Instant credential theft | T1078            | Reassemble FTP streams                   |
| `smtp.auth.password`                      | Mail creds exposure    | Stolen email logins      | T1078            | Inspect SMTP AUTH packets                |
| `http.request.method == "POST"`           | Web form submissions   | Creds/PII exfil          | T1041            | Follow TCP stream; look for creds/tokens |
| `pop or imap`                             | Legacy mail protocols  | Weak/cleartext logins    | T1078            | Capture login sequences                  |
| `kerberos`                                | Kerberos AS-REQ/REP    | Spray, Kerberoasting     | T1110, T1558.003 | Spot AS-REQ failures; RC4 tickets        |

## 4️⃣ Lateral Movement & Internal Abuse

| Filter           | What it does    | Why it matters 🚨          | MITRE ATT\&CK     | Investigate                       |
| ---------------- | --------------- | -------------------------- | ----------------- | --------------------------------- |
| `smb`  | SMB v1   | Windows file sharing/auth | T1021.002   | Watch `Tree Connect`, `Write`, `IPC$` |
| `smb2` | SMB v2   | Newer SMB protocol        | T1021.002   | Check for lateral movement & file ops |
| `tcp.port==3389` | RDP             | Remote access, brute force | T1021.001         | Count failed vs success; duration |
| `winreg`         | Remote Registry | Persistence, tampering     | T1112             | Correlate with new services       |
| `dcerpc` | RPC      | Windows RPC service enumeration / pipe creation (used in lateral movement)     | T1569       | Inspect pipes & service creation |
| `rpc`    | RPC      | General Remote Procedure Calls.Broader RPC, not just Windows | T1569       | Look for remote execution abuse  |
| `ms-wbt-server`  | RDP negotiation | Session profiling          | T1021.001         | Extract build numbers, NLA usage  |

## 5️⃣ Malware Delivery & Tooling

| Filter                                                 | What it does           | Why it matters 🚨          | MITRE ATT\&CK | Investigate                |
| ------------------------------------------------------ | ---------------------- | -------------------------- | ------------- | -------------------------- |
| `http.request.uri contains ".exe" or ".ps1" or ".bat"` | Script/binary download | Malware delivery           | T1105         | Export objects; hash check |
| `tcp.port==69`                                         | TFTP                   | Simple payload transfer    | T1105, T1570  | Reassemble files           |
| `tls.handshake.extensions_server_name`                 | Extract SNI            | Identify hidden C2         | T1071.001     | Pivot SNI with intel       |
| `http contains "powershell" or "cmd.exe"`              | LoLbins referenced     | Scripted delivery/webshell | T1059         | Look for encoded commands  |

## 6️⃣ Command & Control (C2) & Beaconing

| Filter                                       | What it does      | Why it matters 🚨   | MITRE ATT\&CK    | Investigate                  |
| -------------------------------------------- | ----------------- | ------------------- | ---------------- | ---------------------------- |
| `tcp.port==4444 or 1337 or 9001`             | Suspicious ports  | C2 reverse shells   | T1571            | Identify backdoor comms      |
| `tls && frame.len in {200..350}`             | Uniform TLS sizes | Encrypted beaconing | T1071.001        | Plot length vs time          |
| `dns.qry.name matches "[A-Za-z0-9+/=]{20,}"` | Encoded domains   | DNS tunneling       | T1071.004, T1572 | Decode; check TXT types      |
| `stun`   | STUN/VoIP | Session Traversal (UDP 3478/5349) | T1071.001   | Look for odd STUN servers |
| `turn`   | STUN/VoIP | Relay protocol used with STUN     | T1071.001   | Suspicious relay activity |
| `webrtc` | STUN/VoIP | Peer-to-peer browser comms (VoIP) | T1071.001   | Spot unusual P2P sessions |
| `ntp`                                        | NTP anomalies     | Beacon timing/sync  | T1498            | Look for spikes, odd servers |


## 7️⃣ Data Exfiltration Patterns

| Filter                                                             | What it does     | Why it matters 🚨 | MITRE ATT\&CK | Investigate               |
| ------------------------------------------------------------------ | ---------------- | ----------------- | ------------- | ------------------------- |
| `ip.src==<victim> && frame.len > 1000 && ip.dst !in <corp_ranges>` | Bulk egress      | Data exfil        | T1041, T1048  | Sum bytes by dst IP       |
| `http.request.method=="POST" && frame.len > 1200`                  | Large posts      | Form/API exfil    | T1041         | Inspect JSON dumps        |
| `smb2.cmd == 5`                                                    | SMB write reqs   | Staging, exfil    | T1074         | Identify file names, user |
| `ftp-data`                                                         | FTP data channel | Legacy exfil      | T1048         | Reassemble files          |

## 8️⃣ Phishing & Initial Access

| Filter                                     | What it does    | Why it matters 🚨   | MITRE ATT\&CK | Investigate                |
| ------------------------------------------ | --------------- | ------------------- | ------------- | -------------------------- |
| `smtp or imap or pop`                      | Mail protocols  | Phishing entry      | T1566         | Review attachments/headers |
| `http.host contains "bit.ly" or "tinyurl"` | URL shorteners  | Phishing redirects  | T1566.002     | Expand redirects           |
| `http.response.code in {301,302,307,308}`  | Redirect chains | Kits, landing pages | T1566         | Follow referrers           |

## 9️⃣ Protocol Abuse & Exploitation

| Filter                     | What it does  | Why it matters 🚨 | MITRE ATT\&CK     | Investigate                      | 
| -------------------------- | ------------- | ----------------- | ----------------- | -------------------------------- | 
| `dnp3 or modbus or s7comm` | ICS protocols | OT attacks        | T0865             | Spot non-standard traffic        | 
| `ldap`  | Auth/Dir | Directory lookups    | T1087       | Enum accounts/groups   |
| `ldaps` | Auth/Dir | Encrypted LDAP (636) | T1087       | Look for bind attempts |
| `tftp`  | Admin Channel | Trivial FTP (UDP/69)            | T1105       | Tool transfer          |
| `smb`   | Admin Channel | SMB file/pipe sharing           | T1105       | Auth + file copy       |
| `winrm` | Admin Channel | Windows Remote Mgmt (5985/5986) | T1105       | Remote shell execution |
| `dhcp`                     | DHCP chatter  | Rogue servers     | T1557             | Multiple offers? Suspicious DNS? | 

## 🔟 Handy Field Extractors

| Goal                      | Field/Filter                           | Use                  |
| ------------------------- | -------------------------------------- | -------------------- |
| Destination domain in TLS | `tls.handshake.extensions_server_name` | Map encrypted flows  |
| HTTP Host header          | `http.host`                            | Identify C2 infra    |
| HTTP User-Agent           | `http.user_agent`                      | Spot tooling         |
| DNS Query Name            | `dns.qry.name`                         | Spot C2 domains      |
| Kerberos user             | `kerberos.CNameString`                 | Spray/roasting pivot |
| DHCP/DNS                | `bootp`                              | DHCP traffic (rogue DHCP detection)        |
|                         | `dns.flags.rcode != 0`               | Failed DNS lookups (possible DGA/C2)       |
| SSL/TLS                 | `ssl.record.version == 0x0301`       | Detect SSLv3/TLS1.0 (weak crypto)          |
| Mail                    | `imap` / `pop`                       | Legacy mail logins in cleartext            |
| Suspicious Payloads     | `http.request.uri contains "base64"` | Look for encoded exfil in HTTP             |
| SMB                     | `smb2.cmd == 3`                      | File read requests (attacker staging data) |
| Weird Ports             | `tcp.port >= 49152`                  | Ephemeral ports (C2 pivoting)              |


---

**Author:** Me :) **-** *“Better at sniffing packets than sniffing opportunities.”* 😏  

*⚡ Future updates guaranteed—because networks are messy and so is my schedule.* 📡💻

