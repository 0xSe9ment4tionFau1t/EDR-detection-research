# EDR Evasion & Detection Research

**Purpose:** Blue-team detection engineering research. This lab was built to understand exactly where a self-hosted EDR + Sysmon stack detects process-based attacks, and where it does not — so those gaps can be closed.

The approach is iterative: deploy the detection stack, validate it fires against baseline techniques, then build a PoC that bypasses each detection layer one at a time. Every evasion step maps back to a specific detection gap and a recommended fix. The PoC itself has been redacted to avoid being used for malicious purposes. The lab was done for educational purposes only.

> Full write-up: [`report/edr_evasion_report.pdf`](report/edr_evasion_report.pdf)

---

## Lab Environment

| Component | Detail |
|---|---|
| Virtualisation | VirtualBox — Windows VM, Bridged Adapter |
| EDR Stack | Self-hosted open-source EDR (Manager + Indexer + Dashboard via Docker) |
| Endpoint Agent | EDR Agent on Windows VM |
| Telemetry | Sysmon (SwiftOnSecurity config) forwarding via eventchannel |

---

## Detection Rules Under Test

**Rule 92052 — Abnormal parent process**
Fires on Sysmon Event ID 1 when `cmd.exe` is launched by any parent not in the allowlist (`explorer.exe` or `cmd.exe` itself).

**Rule 92032 — Suspicious binary execution**
Fires on Sysmon Event ID 1 when known recon binaries (`whoami`, `hostname`, `net`, `ipconfig`, etc.) appear as child processes.

---

## PoC Technique Stack — Iterative Bypass

Each version added one evasion layer, confirmed it in the EDR dashboard, then moved on.

| Version | Technique Added | Rule 92052 | Rule 92032 | Alerts |
|---|---|---|---|---|
| v1 | HWBP (DR0) + direct syscall (Hell's Gate SSN) + caret obfuscation | Fires | Fires | 2 |
| v2 | + PPID spoofing (`explorer.exe` as fake parent) | **Silent** | Fires | 1 |
| v3 | + No child process (`cmd.exe` built-ins + env vars only) | **Silent** | **Silent** | **0** |

### Technique Detail

**Hardware Breakpoint (DR0)**
Sets a breakpoint on a local function via `SetThreadContext`, triggering execution through a Vectored Exception Handler instead of a standard call. Eliminates the `EXCEPTION_BREAKPOINT` signature produced by software breakpoints.

**Direct Syscall — Hell's Gate + Halo's Gate**
Resolves syscall numbers (SSNs) at runtime by reading `ntdll.dll`'s export stub bytes. Falls back to Halo's Gate (scanning adjacent stubs) when the target stub is hooked. Process creation is called via a runtime-assembled syscall stub rather than through `CreateProcess` or `ntdll`. Sysmon's kernel driver still captures the event — direct syscalls bypass user-mode hooks, not kernel-level telemetry.

**PPID Spoofing**
Opens a handle to `explorer.exe` with `PROCESS_CREATE_PROCESS` access and passes it as `PS_ATTRIBUTE_PARENT_PROCESS` in the `NtCreateUserProcess` attribute list. The kernel records `explorer.exe`'s PID as the new process's parent in the PCB. Sysmon reads the PCB — not the actual calling process — and logs `explorer.exe` as `parentImage`, satisfying Rule 92052's allowlist.

**No Child Process Spawning**
Replaces external recon binaries (`whoami.exe`, `hostname.exe`) with `cmd.exe` built-in commands and environment variable expansions (`%USERNAME%`, `%COMPUTERNAME%`, `%USERDOMAIN%`). These execute inside the existing `cmd.exe` process with no fork and no new PID. Sysmon generates exactly one Event ID 1 for `cmd.exe` itself — nothing beneath it for Rule 92032 to match.

---

## Source File

[`src/PoC.c`](src/PoC.c) — Final PoC (v3): full technique stack.

```c
// Compile on Windows with MinGW/GCC:
gcc PoC.c -o PoC.exe -masm=intel -Wall -lntdll
// Optional: compress to reduce AV surface
upx --ultrabrute poc.exe
```

Output is written to `C:\Windows\Temp\out.txt`. Read with:
```
type C:\Windows\Temp\out.txt
```

**Expected result:** Rule 92052 → silent. Rule 92032 → silent. Sysmon Event ID 1 count → 3 (one per `cmd.exe` payload, zero children each).

---

## Detection Gaps & Fixes

| Gap Exploited | Recommended Fix |
|---|---|
| PPID spoofing evades parent-child rules | Correlate grandparent PID: flag when `explorer.exe`'s own parent is a non-system binary |
| No child process — env var recon is invisible | Monitor `cmd.exe` instances with no child that write to disk (Sysmon Event ID 11) |
| Direct syscall bypasses user-mode hooks | Kernel ETW telemetry captures syscalls regardless of API path |
| RWX memory page for syscall stub | Alert on `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` from non-system processes |
| Hardware breakpoints via DR registers | Monitor `SetThreadContext` calls modifying DR0–DR3/DR7 from user-mode processes |
| Caret obfuscation breaks content rules | Normalise command lines before matching: strip carets, expand `%vars%`, lower-case |

### Architectural Recommendations

**Kernel ETW telemetry** — ETW captures syscall activity at the kernel level, independent of which API path was used. Direct syscalls that bypass `ntdll` hooks are still visible via ETW. Tools like SilkETW can integrate alongside a Sysmon stack to close the user-mode blind spot.

**File write monitoring** — The v3 payload writes to `C:\Windows\Temp\`. Sysmon Event ID 11 would log this. An EDR rule alerting on file creation in Temp by `cmd.exe` instances with no prior child process events in the same session catches the file-based output even when process creation events are clean.

**Call stack analysis** — Commercial EDR products can analyse the call stack at the moment of a syscall. A `SYSCALL` instruction with no `ntdll` frame above it is a strong anomaly signal. This is the primary capability gap between a Sysmon-based stack and products like CrowdStrike Falcon or SentinelOne for detecting direct syscall evasion.

---

## Key Findings

- Sysmon's kernel driver captures process creation events regardless of whether `CreateProcess` or `NtCreateUserProcess` is used — **direct syscalls do not bypass kernel-level telemetry**.
- Rule 92052's two-entry parent allowlist is insufficient against PPID spoofing. Grandparent correlation or session-level process tree analysis is required.
- Eliminating child process spawning removes the primary signal Rule 92032 relies on. There is no detection for recon that never forks.
- The combination of PPID spoofing + no child processes + HWBP + direct syscall produced **zero EDR alerts** while successfully collecting host reconnaissance data.
- The most effective defensive response is not better regex — it is adding a telemetry layer (kernel ETW or call stack analysis) that operates independently of the parent-child relationship model.

---
