
# Recon

Deliberately compromising a computer or server doesn't happen quickly.  Both sides (attackers / redteam vs defenders / blueteam) follow a standard methodology when it comes to compromising. Red team has many blockades to workaround, and blue team has to make sure a large surface area remains impenetrable.

## Methodology
*Gathered from [HackTricks.xyz](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/generic-methodologies-and-resources/pentesting-methodology.md)*

The methodology of pentesting involves a LOT of steps:
- There's host discovery (already done before nmap)
- Port scan
- Service version exploitation
- Phishing (if needed)
- Getting shell
- Init exfiltration
- Privilege escalation
- Post exfiltration
- Pivoting
For this, we can simplify it to about 4 steps:
- Reconaissance is about getting information on the host. *What programs are running, how recently were they updated, etc.*
- Enumeration *Which of these prigrams can be tricked, or are set up incorrectly?*
- Exploitation *Scripting and exploiting that vulnerability to get passwords, or a basic user account*
- Privilege escalation *Once inside, find another bug or misconfiguration to bring you root-- the highest admin level on any machine*

Recon is about **reducing the unknowns**. Just like a burglar scopes out the house, you have to ==scope out the machine== to find potential open doors.
# Port Scanning

To clarify, **discovering the host** you intend to attack comes **before** port scanning, but oftentimes with labs and practice, ==you will already be given the address of the target==.

Port scanning is the process of finding all open entry points. Servers need to communicate, and they do so through ports. Every cyberattack you've ever read started with someone finding the right service to poke -- that's what nmap helps with.
# Network basics

## Servers
Let's imagine your device as a customer going to visit a store or business.

A server is like the **business complex** you are visiting. 
The IP address is the **street address** of this complex. 
Each service is a **business operating in the building**.
Each service has a port it communicates with clients through, just like each **business has a room number it operates at** for customers to come to.
Each port can be:
- Open (the business is **operating and accepting customers**)
- Closed (the business is **operating and temporarily closed**)
- Filtered (a security guard is posted outside **not letting you access the room**)
- Nonexistent (that room number **doesn't exist**, or the complex **doesn't have a business operating at that room**)
> [!note] Public and Private IP addresses
> There’s a catch-- not all server addresses are public. Some are private, meaning they’re used inside home or corporate networks, like an office building with only a back entrance for authorized employees rather than a front desk for the public. Those  servers aren’t directly reachable from the internet. But for today, just think of IPs as the public addresses we can map with Nmap.

# Nmap

I'll be throwing those more technical terms around for this bit:
## Port Scanner
At it's core, nmap is sending packets of information to all ports on the target. Then, it waits for all the responses:
- `Open` means the service is on and communicating
- `Closed` means there is a service, but it is not communicating.
- `Filtered` can mean there was an error, but it almost always means a firewall blocked the packet from ever reaching the service.

It then presents all it's findings in a digestible terminal segments, or can be generated as a log on your computer.

*Walkthgrough 1*
## Flags
The way you adjust the scans are through flags. Thrown onto the end of the command, nmap uses these to find service versions, operating systems, and even run scripts against ports it finds open.

*Walkthrough 2-5*
# TCP

I want to highlight *how* nmap actually collects this information, and it's all through the magic of TCP. What we have been running is a type of port scan called a **TCP connect scan**, also known as a **full open scan**.

The magic here is in TCP, which uses what’s called the **three-way handshake**. I just said a lot of words, so let’s break it down.

## What is TCP?
TCP stands for **Transmission Control Protocol**. It’s a networking protocol that defines how computers start conversations, keep them going, and end them. The rules for starting and establishing a conversation are known as the **three-way handshake**. And this is what nmap actually uses to check if ports are open.

Here’s how it works:
- Let’s say this is a web server hosting 
- If I want to visit that website, my computer has to start a conversation with the server.
- I send the server a **SYN packet** (synchronization message) — basically, “Hey, I’d like to talk. Are you there?”
- Because it’s a web server, I’ll try port **443** (HTTPS).
- If the server is listening on that port, it responds with a **SYN-ACK** — “Yep, I’m awake. I’m here. Let’s talk.”
- Then I reply back with an **ACK** — “Great, I’m ready.”

That’s the **three-way handshake**: SYN → SYN-ACK → ACK. And that’s how nmap figures out if a port is open when you run **-sT**.

*Walkthrough 6*

---
## Nmap Stealth Scan

There’s one problem: scans like this can be a little **loud** on a network. Security systems — like an IDS (Intrusion Detection System) built into a firewall — might notice and flag you.

So what if we want to be more **stealthy**?

Instead of **-sT**, we can use **-sS** (lowercase s, uppercase S). That’s the **stealth scan**, also called a **SYN scan** or **half-open scan**.

Here’s the difference:

- With **-sT**, nmap completes the entire three-way handshake (full TCP connection).
- With **-sS**, nmap starts the handshake but never finishes it.
    - It sends a **SYN packet** to the target port (say, port 80).
    - If the host replies with a **SYN-ACK**, that means the port is open.
    - Instead of finishing with an ACK, nmap just walks away — it never completes the handshake.

Since no full TCP connection is established, it’s **harder for firewalls or intrusion systems to notice**. That’s why it’s called a stealth or half-open scan.

Now, modern firewalls and security tools have gotten smarter, so sometimes they can still detect this. But in many cases, it’s a way to slip under the radar.

*Walkthrough 7*

---