# ProcessGuard — User-mode / Kernel-mode EDR

## 🎯 Project Objective

ProcessGuard is a **full-stack EDR** (Endpoint Detection and Response) built from scratch as a personal learning project during my cybersecurity studies. It implements the same hybrid architecture used by commercial EDR solutions: a **C agent** collecting telemetry via ETW, a **KMDF kernel driver** providing self-protection and real-time blocking, a **Python backend** handling scoring and correlation, and a **React dashboard** for visualization and response.

> **Philosophy**: Learn by doing. Every line of code is an opportunity to understand a Windows mechanism. No vibecoding — everything is built methodically from first principles.

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  FRONTEND (React / TypeScript)                               │
│  Dashboard · Process Tree · Alerts · Rules · Policy Viewer   │
├──────────────────────── WebSocket / REST ─────────────────────┤
│  CONTROLLER (Python / FastAPI)                               │
│  Policy Engine · Scoring · Correlation · YARA · Sigma · DB  │
├──────────────────────── HTTP / WebSocket ─────────────────────┤
│  AGENT (C / Win32 / User-mode)                               │
│  ETW Consumer · Local Decision Engine · Scanner · Transport  │
├──────────────────────── FilterCommunicationPort ──────────────┤
│  DRIVER (C / KMDF / Kernel-mode)                             │
│  Self-Defense · Process/Thread/Image Callbacks · Blocklist   │
└──────────────────────────────────────────────────────────────┘
```

### Decision Model — Local vs Distant

Blocking decisions are **always local**, never over the network. The controller pushes policies; the agent and driver enforce them autonomously.

| Level | Where | Latency | What |
|-------|-------|---------|------|
| 1 — Kernel blocklist | Driver (ring 0) | < 0.1 ms | Hash/path lookup in kernel memory |
| 2 — Local decision engine | Agent (ring 3) | < 5 ms | Policy rules evaluation (parent chain, cmdline, signature) |
| 3 — Full scoring | Controller (network) | 100-500 ms | Correlation, YARA, Sigma, threat intel — **after the fact** |

> The agent and driver keep protecting the endpoint even when the controller is unreachable.

## 📚 Learning Approach

### Reference Material
- **Windows Internals, Part 1** (7th ed.) — Russinovich, Solomon, Ionescu
  - Chapter 1: Concepts and Tools ✅
  - Chapter 2: System Architecture ✅
  - Chapter 3: Processes and Jobs 🔄
  - Chapter 5: Memory Management (planned)
- **Windows Kernel Programming** — Pavel Yosifovich
- **Evading EDR** — Matt Hand (offensive perspective to inform defensive design)

### Development Approach
- **100% of code written by me** — No automated code generation
- **Guided by Claude (Anthropic)** for project structure, documentation references, concept validation, and Socratic debugging
- Concepts are studied and quizzed before implementation

## 🔍 Features

### Agent (C / Win32)
- [ ] ETW consumer: process creation/termination, thread, image load (Microsoft-Windows-Kernel-Process)
- [ ] Multi-provider ETW architecture (Registry, File, .NET, PowerShell — progressive)
- [ ] Property parsing: PID, PPID, CommandLine, ImagePath
- [ ] HTTP transport with batch telemetry and local buffering
- [ ] WebSocket command reception and policy updates
- [ ] Local decision engine with cached policies (< 5 ms evaluation)
- [ ] Communication port to kernel driver (FilterConnectCommunicationPort)
- [ ] Process enumeration and memory scanning (RWX, unmapped PE detection)
- [ ] Handle enumeration (NtQuerySystemInformation)
- [ ] Graceful degradation: works with or without driver, with or without controller

### Driver (C / KMDF)
- [ ] Self-defense via ObRegisterCallbacks (prevent agent termination)
- [ ] PsSetCreateProcessNotifyRoutineEx (process creation notification + blocking)
- [ ] PsSetCreateThreadNotifyRoutine (remote thread injection detection)
- [ ] PsSetLoadImageNotifyRoutine (DLL load monitoring)
- [ ] Kernel blocklist: in-memory hash table for instant blocking (< 0.1 ms)
- [ ] FilterCommunicationPort for bidirectional agent communication
- [ ] Fail-open design: if agent is unresponsive, allow everything

### Controller (Python / FastAPI)
- [ ] REST API: agents, telemetry, events, alerts, actions, rules, policies
- [ ] Policy engine: rule compilation, versioning, push via WebSocket
- [ ] Scoring engine with pluggable scorers (14 scorers, MITRE-mapped)
- [ ] Correlation engine (temporal window, multi-source: ETW + driver)
- [ ] YARA integration for memory dump scanning
- [ ] Sigma rules support (pySigma)
- [ ] PostgreSQL + Redis + Alembic migrations

### Frontend (React / TypeScript)
- [ ] Real-time dashboard with WebSocket
- [ ] Interactive process tree viewer (D3.js)
- [ ] Alert management with MITRE ATT&CK mapping
- [ ] Agent management with driver status and policy version
- [ ] Rule editor with YARA syntax highlighting (Monaco Editor)
- [ ] Policy viewer with version history

## 🛠️ Technical Stack

| Component | Technologies |
|-----------|-------------|
| Agent | C, Win32 API, ETW, WinHTTP, cJSON, fltlib |
| Driver | C, WDK, KMDF, FltMgr |
| Controller | Python 3.11+, FastAPI, SQLAlchemy, Redis, yara-python, pySigma |
| Frontend | React 18, TypeScript, TailwindCSS, Recharts, D3.js, Zustand |
| Database | PostgreSQL (prod) / SQLite (dev) |
| Infrastructure | Docker Compose (controller + frontend + DB) |

## 🔬 Detection Techniques

### Code Injection — T1055
- `PAGE_EXECUTE_READWRITE` in private memory regions
- PE headers ("MZ") in non-`MEM_IMAGE` regions (reflective loading)
- Remote thread creation detected via ETW + driver thread notify callback

### Credential Dumping — T1003
- Handles to `lsass.exe` with `PROCESS_VM_READ`
- File access to SAM/SYSTEM/NTDS.dit hives

### Defense Evasion — T1036 / T1562
- Unsigned binaries with elevated privileges
- Attempts to terminate or access the agent process (detected by driver self-defense)

### Execution — T1059
- Suspicious parent chains (WINWORD.EXE → cmd.exe → powershell.exe)
- PowerShell command-line patterns (-enc, -nop, iex, downloadstring)
- .NET assembly loading in unexpected processes

### Persistence — T1547
- Registry writes to Run/RunOnce/Services keys (ETW Registry provider)

### Command and Control — T1071
- Network beaconing detection (regular outbound connection intervals)

## 📊 MITRE ATT&CK Coverage

| Technique | ID | Detection Source |
|-----------|-----|-----------------|
| DLL Injection | T1055.001 | Memory scanner |
| Thread Execution Hijacking | T1055.003 | ETW + Driver |
| Process Hollowing | T1055.012 | Correlation engine |
| LSASS Memory | T1003.001 | Handle scanner |
| SAM/Registry | T1003.002 | ETW File provider |
| PowerShell | T1059.001 | ETW PowerShell + Scoring |
| Masquerading | T1036 | Signature scoring |
| Disable Security Tools | T1562.001 | Driver self-defense |
| Registry Run Keys | T1547.001 | ETW Registry provider |
| Reflective Code Loading | T1620.001 | Memory scanner |

## 📊 Progress

```
[████░░░░░░░░░░░░░░░] ~15%

✅ Phase 0: Setup & Architecture (monorepo, environments)
🔄 Phase 1: Agent ETW Core (ETW session, parsing, transport)
⬜ Phase 2: Controller Backend (API, DB, WebSocket, policy engine)
⬜ Phase 3: Process Enumeration & Memory Scan
⬜ Phase 4: Driver Kernel (self-defense, callbacks, blocklist)
⬜ Phase 5: Behavioral Analysis (local decision engine, scoring, correlation)
⬜ Phase 6: Frontend Dashboard
⬜ Phase 7: Response Actions (local blocking, remote kill/isolate)
⬜ Phase 8: Tests & Validation (unit, offensive, driver, offline protection)
⬜ Phase 9: Advanced (Authenticode, network ETW, threat intel, Sigma, minifilter)
⬜ Phase 10: Documentation & Publication
```

## 🎓 Windows Internals Concepts Explored

| Concept | Chapter | Application in ProcessGuard |
|---------|---------|----------------------------|
| EPROCESS / KPROCESS | 3 | Internal process structures |
| PEB (Process Environment Block) | 3 | Minimal process detection |
| Object Manager | 3 | Handle enumeration |
| Memory Manager | 5 | Memory page scanning |
| Security (Tokens, SIDs) | 3 | Privilege analysis |
| ETW Architecture | 3 | Real-time telemetry collection |
| Kernel Callbacks | 3 | Driver process/thread/image notify |
| Object Callbacks | 3 | Driver self-defense (ObRegisterCallbacks) |

## 🚧 Acknowledged Limitations

- ⚠️ Driver runs in **test signing mode** only (no WHQL/ELAM signature)
- ⚠️ No access to the ETW Threat Intelligence provider (requires PPL)
- ⚠️ Single-agent tested (multi-agent management is Phase 9)
- ✅ Effective detection via ETW + kernel callbacks + memory scanning
- ✅ Real-time blocking via driver + local decision engine
- ✅ Autonomous protection when controller is unreachable

## 📖 Documentation

- `docs/architecture.md` — System architecture (4 layers)
- `docs/decision-model.md` — Local vs distant decision model, policy push
- `docs/driver-architecture.md` — Kernel callbacks, communication port, self-defense
- `docs/etw-coverage.md` — ETW providers, opcodes, progressive implementation strategy
- `docs/etw-notes.md` — Personal ETW learning notes (Provider/Controller/Consumer model)
- `docs/scoring.md` — Scoring engine and scorer descriptions
- `docs/api.md` — Controller REST API reference

## 🔗 Resources

### Books
- *Windows Internals, Part 1* (7th ed.) — Russinovich, Solomon, Ionescu
- *Windows Kernel Programming* — Pavel Yosifovich
- *Evading EDR* — Matt Hand
- *The Art of Memory Forensics* — Halderman et al.

### Technical Resources
- Matt Graeber / SpecterOps — ETW analysis and evasion
- Elastic Security Blog — Behavioral detection research
- OSR Online — Kernel driver development
- SilkETW (FuzzySecurity) — ETW wrapper reference
- Process Hacker (phnt headers) — Native API definitions

### Frameworks & Standards
- MITRE ATT&CK — Adversarial technique framework
- Sigma Rules (SigmaHQ) — Detection rule standard
- YARA — Binary pattern matching
- Atomic Red Team — Adversary emulation

## ⚖️ Disclaimer

**Ethical use only.** This tool is developed within a defensive cybersecurity learning and research framework. Any malicious use is strictly prohibited.

Testing is performed exclusively on:
- My own systems in isolated VM environments (with snapshots)
- Malware samples from MalwareBazaar in throwaway VMs
- In accordance with responsible security research practices

## 📜 License

GNU GPL v3 — See [LICENSE](LICENSE) for details.

---

**Last Update**: 03/19/2026
**Status**: 🔄 Phase 1 — Agent ETW Core
**Topics**: `windows-internals` `edr` `security` `etw` `kernel-driver` `malware-detection` `fastapi` `react` `cybersecurity`
