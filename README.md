# Tasklet

Tasklet is a native Windows process monitor, kernel telemetry dashboard, and unauthorized-process defense engine. The desktop application runs without the optional kernel driver and collects all resource counters through documented Windows APIs. When the driver is present it supplements the UI with kernel-level event streams.

## Build the application

```powershell
cmake -S . -B build -A x64 -G "Visual Studio 16 2019"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

All four targets are built together:

| Binary | Purpose |
|--------|---------|
| `tasklet.exe` | Full futuristic HUD desktop application |
| `unauprocdetect.exe` | Standalone unauthorized-process CLI sentinel |
| `tasklet_protocol_tests.exe` | Unit tests for telemetry protocol |
| `unauprocdetect_tests.exe` | Unit tests for detection engine |

## Desktop application — Futuristic Sci-Fi HUD

The main window (`tasklet.exe`) is a full dark Cyberpunk / Sci-Fi HUD with 8 navigation pages rendered via double-buffered GDI:

| # | Page | Description |
|---|------|-------------|
| 0 | **OVERVIEW** | Cyber command overview — live kernel event stream, UNAU threat gauge, system pulse |
| 1 | **UNAU SENTINEL** | UnauProcDetect live findings dashboard — unauthorized processes, threat scoring |
| 2 | **PROCESSES** | Full process list with CPU/mem/I/O, tree view (press `T`), filter panel |
| 3 | **PERFORMANCE** | CPU/Memory/Disk/Network real-time sparkline graphs |
| 4 | **KERNEL MONITOR** | Live kernel event log with event kind badges and timestamps |
| 5 | **NETWORK SENTINEL** | TCP/UDP socket table with process correlation and unauthorized flags |
| 6 | **DETAILS** | Deep per-process forensics: path, hash, signer, command line, I/O counters |
| 7 | **THREADS** | Per-thread CPU time for the selected process |

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `1`–`8` | Switch page |
| `T` | Toggle process list / tree view (Processes page) |
| `Del` | Terminate selected process |
| `F5` | Force refresh process list |

## UnauProcDetect — Unauthorized Process Sentinel

`unauprocdetect.exe` is a standalone CLI tool and the detection engine embedded in the GUI.

### Detection rules

| Rule | Trigger |
|------|---------|
| `UNAU-001` | Executable running from a temp or user-writable path |
| `UNAU-002` | Name masquerades as a known Windows system binary |
| `UNAU-003` | Typosquatting of common system process names |
| `UNAU-004` | Unsigned executable (Authenticode + catalog check) |
| `UNAU-005` | Suspicious command-line patterns (encoded payloads, LOLBin abuse) |
| `UNAU-006` | Anomalous parent-child spawn relationship |

### CLI usage

```powershell
# Quick scan — all running processes
unauprocdetect.exe --scan

# Deep forensic scan with Authenticode + SHA-256
unauprocdetect.exe --deep

# Continuous real-time monitoring daemon
unauprocdetect.exe --monitor

# Terminate a specific process
unauprocdetect.exe --kill 4812

# Monitor and auto-terminate CRITICAL threats
unauprocdetect.exe --auto-kill

# JSON report
unauprocdetect.exe --json > audit_report.json

# Add a whitelist path or name
unauprocdetect.exe --whitelist "C:\MyApp\app.exe"
```

## Kernel driver — continuous kernel monitor

`driver\TaskletDriver.c` is an enhanced KMDF driver that continuously monitors the kernel and emits telemetry events:

| Event kind | Source |
|-----------|--------|
| `TaskletProcessStarted (1)` | `PsSetCreateProcessNotifyRoutineEx` |
| `TaskletProcessExited (2)` | Process exit callback |
| `TaskletThreadStarted (3)` | `PsSetCreateThreadNotifyRoutine` |
| `TaskletThreadExited (4)` | Thread exit callback |
| `TaskletImageLoaded (5)` | `PsSetLoadImageNotifyRoutine` — every DLL/EXE mapped into any process |
| `TaskletKernelHeartbeat (6)` | 1-second periodic KTIMER + DPC — confirms driver is alive |

When the driver is unavailable the `TelemetryClient` falls back to a user-mode NT co-monitor that polls the process snapshot every 150 ms and emits equivalent `ProcessStarted`/`ProcessExited` events plus a 1-second heartbeat.

### Driver management script

```powershell
# Check driver status
.\scripts\manage_driver.ps1 status

# Install and start (requires test-signed build, test-signing mode)
.\scripts\manage_driver.ps1 install
.\scripts\manage_driver.ps1 start

# Stop and uninstall
.\scripts\manage_driver.ps1 stop
.\scripts\manage_driver.ps1 uninstall
```

### Building the driver (requires WDK)

```powershell
msbuild driver\TaskletDriver.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Requires: Visual Studio with **Windows Driver Kit (WDK)** installed alongside it. Not required for the application or unauprocdetect builds.

## Windows and deployment assumptions

- Target: Windows 10 22H2 / Windows 11, x64
- Build tools: Visual Studio 2019 Build Tools, MSVC 14.29, Windows SDK 10.0.19041
- Driver requires WDK (separate install); app and CLI tools build without it

Kernel drivers must meet Windows signing policy. A development build requires test-signing mode enabled on a disposable VM. Do **not** install experimental driver builds on a production machine.
