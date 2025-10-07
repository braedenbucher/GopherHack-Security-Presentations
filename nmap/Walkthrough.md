*Run inside VMWare Workstation 17.6 ProWIth Kali Linux 2025.2*
*Nmap 7.95
*Wireshark 4.4.9*
*Wireshark is scanning VMWare's`tun0` Wifi adapter*.

# Walkthrough

## 1
To start, we can just throw `nmap [IP]` into the terminal
![[Walkthrough-nmap1.png]]
![Example 1](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-nmap1.png)

Highlight:
- `Host  is up (0.035s latency)` indicating a ping scan was done.
- `Not shown: 998 closed tcp ports (reset)` showing the default is top 1k
- Table showing open ports and their services

## 2
We can add some flags: `-sV` enumerates software versions.
![[Walkthrough-nmap2.png]]
![Example 2](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-nmap2.png)

## 3
`-vv` gives a more in-depth discovery, showing the status of the scans  as they happen
![[Walkthrough-nmap3.png]]
![Example 3](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-nmap3.png)

## 4
`-O`  pokes at the operating system of the machine.
![[Walkthrough-nmap4.png]]
![Example 4](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-nmap4.png)

## 5
Some flags are even bundled, `-A` does version enumeration, but a few other things:
![[Walkthrough-nmap5.png]]
![Example 5](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-nmap5.png)

Highlight:
- Ports have more info below them-- scripts were run against the ports, with titles showing what script was run
- Traceroute table establishes all network hops it took to get there


## 6
If we run Wireshark, a network scanner to see all these packets Nmap sends, here is what we catch. We use the `-sT` flag to force Nmap to run the  entire TCP Handshake.

```
nmap -sT 10.10.11.86
```
![[Walkthrough-wireshark1.png]]
![Example 6](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-wireshark1.png)

Highlight:
- 3 way shake, showing port sending
- RST to cut connectio

## 7
If we turn Wireshark back on, but this time use the flag `-sS`, the stealthy scan executes.
![[Walkthrough-wireshark2.png]]
![Example 7](https://github.com/braedenbucher/GopherHack-Security-Presentations/blob/main/nmap/images/Walkthrough-wireshark2.png)

Highlight:
- RST thrown before third shake
