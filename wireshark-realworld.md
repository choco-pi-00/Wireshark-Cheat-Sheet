# 📑 Index

- [🏢 Where Wireshark is Used in a Company](#-where-wireshark-is-used-in-a-company)

- [🎯 Roles where Wireshark is Used](#-roles-where-wireshark-is-used)
  - [🕵️ SOC Analyst / Blue Team](#-soc-analyst--blue-team)
  - [🔥 Incident Response / Forensics](#-incident-response--forensics-1)
  - [🐱‍💻 Penetration Tester / Red Team](#-penetration-tester--red-team)
  - [🛠️ Network Engineer (Troubleshooting)](#️-network-engineer-troubleshooting)
- [📚 Extra Resources](#-extra-resources)



# 🏢 Where Wireshark is Used in a Company


###  🧪 On a Sandbox / Test Machine (sometimes your own laptop/VM)

- If you’re in SOC / Blue Team, you’ll often capture packets from your own system or a test machine to analyze suspicious traffic.

- Example: Suspected malware making connections → run Wireshark to check DNS requests, IPs, ports.

` Good for malware analysis. Bad if you forget Wireshark is running during Netflix binge. 🍿`

### 💻 On a Server / Critical Machine

- If there’s suspicious activity (data exfiltration, weird logins, brute-force), Wireshark is run directly on the server under investigation.

- Example: A web server receiving strange requests → run Wireshark to filter HTTP payloads.

` Pro tip: Don’t leave Wireshark running overnight on a busy server, unless you enjoy 100GB log files. 💾 `

### 🌐 At the Network Level (SPAN / Mirror Port on Switch / TAP)

- In a company, you don’t sniff everyone’s traffic from your laptop directly 😅

- Instead, network admins configure a **SPAN (port mirroring)** on a switch/router → it **copies all network traffic** to a dedicated analysis machine where Wireshark runs.

- This way you can analyze company-wide traffic without interfering.

` It’s like sitting in the CCTV room, but for packets. 🎥`

### 🛡️ Packet Captures from IDS/IPS or Firewalls

- Tools like **Suricata, Snort, Palo Alto, Cisco Firepower** generate .pcap files.

- You load those .pcap files into Wireshark and apply your filters to find malicious/suspicious packets.

` Because firewalls love saying “suspicious traffic detected”… but never explain what it means. 😒 `

### 🔴 Incident Response / Forensics

- When there’s a **breach**, you’ll often be given a **PCAP dump** from the network team → your job is to analyze it with Wireshark.

- Example: Checking if data was exfiltrated, which IP attacker used, which exploit port was targeted.

` If you’re lucky, attacker used Telnet. If unlucky, they used encrypted tunnels. RIP. 🪦 `


--- 
# 🔍 How Companies Actually Capture Traffic


In real-world SOC/blue team work, analysts don’t sit on their laptops capturing their own Netflix traffic.
Instead, they use SPAN / Mirror ports or tap devices to **grab copies of traffic from production servers**.

Think of it like this:

- **Normal switch** = A post office 📮 → it only delivers letters to the intended recipient.

- **SPAN port** = The post office clerk makes a **photocopy of every letter ✉️** → and secretly hands it to the SOC analyst.

- **Analyst’s Wireshark machine** = The detective 🕵️‍♂️ reading through those letters, looking for suspicious messages like:

    - “Password123” in plaintext 🤦

    -  Unknown IPs sending too much traffic 🌊

    -  Malware calling home to shady domains 🕸️

**📌 Example scenario:**
A company suspects their web server is under attack (maybe SQL injection or brute force).

Network team configures the switch:

    - Source = Web server’s port

    - Destination = Analyst’s port

Analyst opens Wireshark and starts filtering:

    - http.request.method == "POST" → to catch suspicious form submissions

    - ip.addr == 45.12.34.56 → to track a suspicious attacker IP

Result? Instead of digging blindly, the analyst has a live CCTV feed of network packets.

---

# 🎯 Roles where Wireshark is used:

## **🕵️ SOC Analyst / Blue Team**

**Scenario:** SIEM (Splunk/QRadar) alerts that one workstation is making suspicious connections to an unknown IP.

- Analyst downloads a pcap from the firewall or runs Wireshark on that machine.

- Uses filters like:

          dns.qry.name               # Show all DNS queries
          dns.qry.name == "evil.com" # Queries for specific domain
          http.request               # Only HTTP requests
          http.host contains "xyz"   # Filter by host header
          ssl.handshake              # SSL/TLS handshakes
          tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN packets (possible scan)


- Finds that the host is sending DNS queries to weird domains and HTTP POST requests with encoded data → indicates malware beaconing.
  
✅ SOC raises an incident → blocks IP/domain on firewall.


## 🔥 Incident Response / Forensics

**Scenario:** Data breach suspected on a file server.

- Network team gives a pcap of server traffic during the suspected time.

- Investigator loads it in Wireshark, applies filters:

        smb || smb2                # File sharing traffic (Windows)
        ftp                        # FTP traffic
        ftp-data                   # FTP file transfers
        kerberos                   # Kerberos authentication
        ip.addr == 10.0.0.5 && http # Victim’s HTTP traffic
        tcp.stream eq 1            # Follow a single TCP conversation



- Finds attacker connected over FTP and downloaded confidential files in plain text.
  
✅ IR confirms data exfiltration.


## 🐱‍💻 Penetration Tester / Red Team

**Scenario:** During an internal pentest, tester sits inside the corporate LAN.

- Runs Wireshark in promiscuous mode on their laptop.

- Filters for:

        ftp || telnet || http      # Insecure protocols (plaintext creds)
        smtp                       # Emails in transit
        pop || imap                # Mailbox access
        kerberos                   # Look for Kerberos tickets
        ntlmssp                    # NTLM authentication attempts
        dhcp                       # DHCP traffic (network mapping)



- Sees plaintext credentials (FTP/Telnet logins).

- Later uses:

        kerberos


- Finds Kerberos tickets being exchanged → checks for weak configurations.
  
✅ Reports insecure protocols + credential leaks.


## 🛠️ Network Engineer (Troubleshooting)

**Scenario:** Employees report network is slow.

- Engineer runs Wireshark on a mirrored switch port.

- Filters for:

        tcp.analysis.retransmission # Detect retransmissions
        tcp.analysis.flags          # TCP analysis issues
        icmp                        # Ping / network connectivity
        arp                         # ARP traffic (duplicate IPs, spoofing)
        bootp                       # DHCP/BootP issues



- Finds huge packet retransmissions caused by misconfigured firewall → fixes it.
  
✅ Network speed restored.

---

# 📚 Extra Resources

**Wireshark Display Filter Reference (cheat sheet of filter magic 🪄)**
👉 https://www.wireshark.org/docs/dfref/

- It’s a *full dictionary of display filters* (like ip.addr, tcp.port, http.request.method) with syntax and meaning.

- Basically your “all spells book” when you forget the filter syntax.

**Wireshark Sample Captures (practice playground 🎮)**
👉 https://wiki.wireshark.org/SampleCaptures

- It’s a library of *real-world PCAP files* (DNS queries, malware traffic, VoIP calls, SMB shares, etc.).

- You can download and **practice** analyzing without needing live traffic.

---
**Author: Me :)**

*“Trust the packets, not the rumors 📡.”*

