  Terminal nmap just follows:
```
(sudo) nmap flags IP
```

Almost all flags can be used interchangeably, just be aware for flags that use parameters.
# Basic Scan

```bash
sudo nmap -sC -sV -vv -oA nmap/box 10.10.10.10
```

## `-sC` 
Runs Nmap's **default scripts**. These scripts can detect generic vulnerabilities, misconfigurations, but primarily extract useful information like SSL certs, HTTP titles, and more. *It's shorthand for `--script=default`.*
## `-sV`
Enables **version detection**.
## `-vv`
Increases **verbosity**.
## `-oA nmap/box`
Outputs the results in **all major formats** (`.nmap`, `.xml`, `.gnmap`) in the folder `nmap` with the filename `box`.  
`nmap/box.nmap` – regular Nmap output       
`nmap/box.xml` – XML (for tools)    
`nmap/box.gnmap` – greppable format (easier to script)        
# Misc

## Basic scan flags

| Command                        | Flag                     |
| ------------------------------ | ------------------------ |
| Top 1000 TCP Ports             | *N/A*                    |
| All 65535 Ports                | `-p-`                    |
| Specific Port                  | `-p 22,80,135`           |
| \*\*UDP Scan                   | `-sU`                    |
| Combine TCP & UDP              | `-sS -sU -p T:1,2,U:3,4` |
| \*Auto Aggressive Scan         | `-A`                     |
| .txt Output                    | `-oN scan.txt`           |
| TCP Full Scan *Full handshake* | `(sudo) -sT`             |
| TCP SYN Scan *Stealth*         | `(sudo) -sS`             |
| Timing                         | `-T1` to `-T5`           |
| OS Detection                   | `-O`                     |
\**Shorthand for  `-sC -sV -O -traceroute`. It runs default scripts, version detection, OS Fingerprinting, traceroute. Noisy if stealth is ever an issue.*

\*\**Identical setup to TCP, empty for top 1000, `-p-` for all ports, etc*

## Multiple Hosts

| Method        | Command                      | Description                        |
| ------------- | ---------------------------- | ---------------------------------- |
| Dash Range    | `nmap 192.168.1.1-50`        | *Scans from lower - upper bound*   |
| CIDR Notation | `nmap 192.168.1.0/24`        | *Scans all 265 IPs in that subnet* |
| Comma List    | `nmap 192.168.1.5,10`        | *Scans only the IPs listed*        |
| Combination   | `nmap 192.168.1.5-10,50,100` | *Scans range + individual IPs*     |
| From File     | `nmap -iL hosts.txt`         | *Pulls ranges from file*           |
## Host Discovery
*Nmap usually sends quite a few probes to make sure hosts are up, these are ways to constrict what nmap probes with to avoid some IDS filters.*

| Method                        | Flag              | Description                  |
| ----------------------------- | ----------------- | ---------------------------- |
| Disable ICMP (Ping) Discovery | `-Pn`             | *Assumes host is already up* |
| ICMP Echo Request Only        | `-PE`             | *Limits Probes*              |
| TCP/UDP Based Discovery       | `-PS80,443 -PU53` | *Sends SYN probes to ports*  |

## Basic IDS Evasion
*Basic ways to evade legacy/misconfigured hosts.*

| Method             | Flag               | Description                                                |
| ------------------ | ------------------ | ---------------------------------------------------------- |
| Decoy Scan         | `-D RND:10`        | *Adds spoofed source IPs + real IP*                        |
| Fragment Packets   | `-f`               | *Legacy trick to hide packets*                             |
| Custom source port | `--source-port 53` | *Bad firewalls trust specific ports*                       |
| Spoof Mac Address  | `--spoof-mac 0`    | *Fakes L2 Hardware address, only on same broadcast domain* |
## Performance
*Reduce redunant defaults if you knwo what you're looking for.*

| Method                 | Flag              | Description                         |
| ---------------------- | ----------------- | ----------------------------------- |
| Specific Packet Rate   | `--min-rate 1000` | *send at least X packets/sec*       |
| Disable DNS Resolution | `-n`              | *avoids noist reverse DNS info*     |
| Max Retries            | `--max-retries 2` | *if no response, try again X times* |
## Specialized Scans
*Neat Scans for specific use cases.*

| Method                         | Flag               | Description                                                                      |
| ------------------------------ | ------------------ | -------------------------------------------------------------------------------- |
| Idle Scan                      | `-sI <zombiehost>` | *Uses an entirely new machine to send packets, your IP never shows up on target* |
| Banner Grabbing (TCP ACK Scan) | `-sA`              | *Uses TCP ACK to fingerprint firewalls and grab banners*                         |
| IP Protocol Scan (non-TCP/UDP) | `-sO`              | *Finds any non-TCP/UDP protocols host supports*                                  |
# Footnotes

## *Privileges Matter*
- SYN scans (`-sS`) and OS detection (`-O`) usually require root/administrator privileges.
- Without root, you fall back to TCP connect scans (`-sT`) which are noisier and easier to detect.

## *Timing vs. Accuracy*
- `-T1`–`-T5` aren’t just speed tweaks—they affect reliability, detection by IDS, and evasion.
    - Fast scans (`-T4`/`-T5`) might miss filtered ports or trigger alarms.
    - Slow scans (`-T0`/`-T1`) are stealthy but painfully slow.

## *Firewalls & Filters*
- A “closed” port in Nmap doesn’t always mean it’s _really_ closed—firewalls can fake responses.
- Sometimes Nmap shows ports as “filtered” even if they’re open but blocked by a packet filter.

## *UDP Scans Are Painful*
- `-sU` can be _very_ slow, especially on large ranges, because UDP has no handshake.
- Expect many “open|filtered” results that require follow-up.

## *NSE Script Coverage*
- Not all scripts are safe to run. Some are intrusive and can break services.
- Default scripts are usually safe, but running `vuln` or `intrusive` scripts on a production system is risky.

## *Version/OS Detection Limits*
- Version detection (`-sV`) and OS detection (`-O`) can be tricked by firewalls or service misconfigurations.
- Always double-check suspicious results—don’t trust Nmap blindly.

## *Output Formats Are Useful for Automation*
- XML is best for machine parsing.
- Greppable (`.gnmap`) is great for quick scripts, but it’s less structured than XML.
- Plain text (`.nmap`) is human-readable and good for notes.

## *DNS Resolution
- Nmap resolves hostnames by default; this can slow scans on large ranges.    
- Use `-n` if you don’t care about names or want speed.

## *Traceroute*
- `-traceroute` can be helpful for mapping network topology, but on filtered networks it may fail or misreport.
- Useful if you want to correlate hosts with firewall segments.