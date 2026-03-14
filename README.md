# ProcessGuard - Mini EDR Detection Engine

## 🎯 Project Objective

This project is a **personal learning exercise** as part of my cybersecurity studies. My goal is to gain deep understanding of Windows internal mechanisms by implementing a detection tool inspired by modern EDR (Endpoint Detection and Response) solutions.

## 📚 Learning Approach

### Methodology
- **Reference Book**: *Windows Internals, Part 1* (7th edition) - Russinovich & Solomon
- **Chapters Studied**: 
  - Chapter 1: Concepts and Tools ✅
  - Chapter 2: System Architecture ✅
  - Chapter 3: Processes and Jobs 🔄
  - Chapter 5: Memory Management (planned)

### Development Approach
- **100% of code written by me** - No automated code generation
- **Guided by Claude (Anthropic)** for:
  - Project structure and roadmap
  - Technical documentation references (MSDN, technical blogs)
  - Windows Internals concept validation
  - Conceptual debugging (no ready-made solutions)
  
> **Philosophy**: Learn by doing. Every line of code is an opportunity to understand a Windows mechanism.

## 🔍 Planned Features

### Phase 1: ETW Monitoring (Event Tracing for Windows)
- [ ] ETW consumer for process creation events
- [ ] Property parsing: PID, PPID, CommandLine, ImagePath
- [ ] Real-time logging of process activities

### Phase 2: Memory Scanning
- [ ] Active process enumeration (PSAPI)
- [ ] Memory region scanning with `VirtualQueryEx()`
- [ ] Detection of suspicious RWX (Read-Write-Execute) pages
- [ ] Identification of unmapped PE (Portable Executable) in memory

### Phase 3: Behavioral Analysis
- [ ] Handle enumeration with `NtQuerySystemInformation()`
- [ ] Detection of suspicious access (handles to lsass.exe, SAM registry)
- [ ] Risk scoring system (0-100)
- [ ] Multiple ETW event correlation

### Phase 4: CLI Interface
- [ ] Command-line arguments (scan/monitor modes)
- [ ] Formatted output (console + JSON)
- [ ] Persistent logging for forensics

## 🛠️ Technical Stack

- **Language**: C (Win32 API + Native API)
- **Windows APIs**:
  - ETW (Event Tracing): `StartTrace()`, `ProcessTrace()`, TDH
  - PSAPI: `EnumProcesses()`, `GetModuleFileNameEx()`
  - Memory: `VirtualQueryEx()`, `ReadProcessMemory()`
  - Native API: `NtQuerySystemInformation()`, `NtQueryInformationProcess()`
- **Environment**: User-mode (no kernel driver)
- **Compilation**: Visual Studio 2026

## 🎓 Windows Internals Concepts Explored

| Concept | Chapter | Application in ProcessGuard |
|---------|---------|----------------------------|
| EPROCESS / KPROCESS | 3 | Internal process structures |
| PEB (Process Environment Block) | 3 | Minimal process detection |
| Object Manager | 3 | Handle enumeration |
| Memory Manager | 5 | Memory page scanning |
| Security (Tokens, SIDs) | 3 | Privilege analysis |
| ETW Architecture | 3 | Real-time monitoring |

## 🔬 Detection Techniques

### Code Injection
- **Indicators**:
  - `PAGE_EXECUTE_READWRITE` pages in private memory
  - PE headers ("MZ") in non-`MEM_IMAGE` regions
  - `CreateRemoteThread` calls detected via ETW

### Credential Dumping
- **Indicators**:
  - Handles to `lsass.exe` with `PROCESS_VM_READ`
  - Access to SAM/SYSTEM registry hives

### Suspicious Behaviors
- **Indicators**:
  - Abnormal parent chains (cmd.exe → powershell.exe)
  - Unsigned binaries with elevated privileges

## 📊 Progress

```
[██░░░░░░░░░░░░░░░░░░] 10% - Phase 0 Complete

✅ Phase 0: Setup & Architecture
⬜ Phase 1: Basic ETW Consumer  
⬜ Phase 2: Memory Scanning
⬜ Phase 3: Behavioral Engine
⬜ Phase 4: CLI & Output
⬜ Phase 5: Testing & Validation
```

*(Last update: Project initialization)*

## 🚧 Acknowledged Limitations

As a **user-mode** learning project:
- ❌ No proactive blocking (no minifilter driver)
- ❌ No tampering protection
- ❌ Limited access to kernel structures (no direct EPROCESS)
- ✅ But: Effective detection via ETW and memory scanning

> **Note**: These limitations are intentional. The goal is to master user-mode fundamentals before tackling kernel development.

## 📖 Documentation

- **[docs/learning-notes.md](docs/learning-notes.md)**: My Windows Internals reading notes
- **[docs/technical-details.md](docs/technical-details.md)**: Detailed technical architecture
- **[docs/detection-techniques.md](docs/detection-techniques.md)**: Detection algorithm explanations

## 🎯 Inspirations

- **SysInternals Suite**: Reference tools (Process Explorer, Process Monitor)
- **Process Hacker**: Open-source process analysis project

## 🔗 Resources Used

### Books
- *Windows Internals, Part 1* (7th ed.) - Russinovich, Solomon, Ionescu
- *Windows System Programming* (4th ed.) - Johnson M. Hart

### Technical Blogs
- Alex Ionescu's Blog (Protected Processes)
- Matt Graeber - SpecterOps (ETW Analysis)
- Hexacorn (Memory Forensics)

### Documentation
- Microsoft Docs: ETW, Win32 API, Native API
- Process Hacker: phnt headers (Native API)
- MITRE ATT&CK: Adversarial technique framework

## 🤝 Contributing

This project is primarily **personal and educational**. However, if you have:
- Conceptual improvement suggestions
- Relevant documentation resources
- Bugs to report

Feel free to open an issue! Pull requests are accepted if they respect the pedagogical approach of the project.

## ⚖️ Disclaimer

**Ethical use only.** This tool is developed within a defensive cybersecurity learning and research framework. Any malicious use is strictly prohibited and contrary to the project's spirit.

Testing is performed only on:
- My own systems in isolated environments
- Malware samples in throwaway VMs (MalwareBazaar)
- In accordance with malware analysis best practices

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🚀 Post-Project Goals

Once ProcessGuard is functional, my next steps:
1. **Internship/Apprenticeship**: Finding an internship or a work-study program in Windows low-level development
2. **Open-Source Contribution**: Contribute to EDR/Windows security projects
3. **Research**: Explore EDR bypasses (red team side to understand blue team)

---

**Last Update**: Project initialization  
**Status**: 🔄 Phase 0 - Setup & Architecture  
**Topics**: `windows-internals` `edr` `security` `etw` `malware-detection` `cybersecurity`
