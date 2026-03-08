# Barbwire
A lightweight eBPF-based tool that watches for processes that open sensitive files and then make network connections shortly after. Built as a learning project to get hands-on with eBPF and kernel-space programming.

## What it does
Barbwire attaches tracepoints to three syscalls, `openat`, `connect`, and `execve`. It then streams events to userspace via a ring buffer. The userspace correlator tracks which processes opened which files, and if the same process makes a network connection within a configurable time window, it checks whether the file access looks suspicious.

If it does, it emits an alert with the process name, the file it opened, the destination it connected to, and the parent/grandparent process chain.

```
┌─ barbwire alert — PID 19535  ─────────────
│  command  : python
│  file     : /etc/passwd
│  connect  : 142.250.67.46:443
│  severity : HIGH
│  reasons  : credential access, suspicious parent: fish
│  parent   : fish (pid 13387)
│  gparent  : tmux: server (pid 9483)
└─────────────────────────────────────────────
```

## How it works
The BPF side is intentionally minimal, it just collects raw event data and writes it into a shared ring buffer. No correlation logic lives in kernel space. All the decision making happens in userspace Go code.

For process lineage, the `execve` hook walks the kernel `task_struct` using CO-RE (Compile Once, Run Everywhere) helpers to read the parent and grandparent process details without hardcoding kernel struct offsets.

Severity scoring is based on file+connect pairs. The idea being that a process connecting to the network is normal, opening `/etc/shadow` is normal in isolation, but doing both within a short window is worth flagging. Lineage modifies the score up or down depending on what spawned the process.

## Limitations
This was a learning experiment, not to be used as a real thing. Where this goes wrong:

- **Lot of false positives**: Legitimate tools like `curl` read `/etc/passwd` on every invocation because glibc's NSS resolver does it internally (I honestly didn't know it did that). The tool will flag this.
- **Using just process name is not a good idea**: An attacker can name their binary anything. A production tool would probably verify it by binary hash or something else.
- **In terms of persistence, we have none**: Correlation state lives in memory and is lost on restart.
- **Looks only at one process at a time**: The tool correlates events within a single PID. It cannot track behavior across a process tree, for example, a shell that exfiltrates data through a child process would not be caught.

The natural next step would be building a full process ancestry graph to track behavioral chains across spawned processes rather than single-process snapshots.

## Configuration
All tunable parameters live in `config.yml`. Just modify it and restart.

## Requirements
- Linux kernel 5.8+ (ring buffer support)
- Root or `CAP_BPF` + `CAP_PERFMON` capabilities
- clang/llvm for compiling the BPF program
- Go 1.21+

## Building
```bash
make run
```
## What I learned
The most interesting part of this project was figuring out the boundary between what should live in kernel space and what belongs in userspace. The first version had correlation logic in BPF, time window checks, hash maps for state. Moving all of that to Go made the BPF code simpler, easier to verify, and more portable.

Another lesson learned was, how hard real detection tools work. I tried tuning the parameters and scoring to get it to work, but I couldn't. Hence, it became clear this isn't a tuning problem, it's the design. Flagging behavior based on file names and process names will always have gaps. Process graph tracking, binary hashing, and behavioral baselines are where the interesting work actually lives. 
