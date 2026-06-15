# Architecture Diagram and Trust Boundaries

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY 1                          │
│                     (Agent Reasoning Layer)                       │
│                                                                   │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────────┐     │
│  │  TRIAGE   │───▶│DEEP ANALYSIS │───▶│   AI ANALYSIS      │     │
│  │           │    │              │    │   (Groq/LLaMA 3.1) │     │
│  │ 4 tools   │    │ 4 tools      │    │   Analyzes findings │     │
│  └──────────┘    └──────────────┘    └─────────┬──────────┘     │
│                         ▲                       │                 │
│                         │   gaps found          │                 │
│                         └───────────────────────┤                 │
│                                                 ▼                 │
│                                      ┌──────────────────┐        │
│                                      │ SELF-CORRECTION   │        │
│                                      │ • PID validation  │        │
│                                      │ • Coverage check  │        │
│                                      │ • Max 3 rounds    │        │
│                                      └────────┬─────────┘        │
│                                               │                   │
│                                    complete    │                   │
│                                               ▼                   │
│                                      ┌──────────────────┐        │
│                                      │ REPORT GENERATOR  │        │
│                                      │ CONFIRMED/INFERRED│        │
│                                      └──────────────────┘        │
│                                                                   │
│  Execution Logger: Every tool call timestamped (UTC)              │
│  Audit Trail: Finding → Tool Execution traceable                  │
└──────────────────────────┬────────────────────────────────────────┘
                           │
                    MCP Protocol (typed function calls only)
                           │
┌──────────────────────────┴────────────────────────────────────────┐
│                        TRUST BOUNDARY 2                            │
│                  (MCP Server — Architectural Enforcement)           │
│                                                                     │
│  EXPOSED FUNCTIONS (agent CAN call):                                │
│  ├── get_process_list(image_path) → structured process data         │
│  ├── get_process_tree(image_path) → parent-child relationships      │
│  ├── get_command_lines(image_path) → command arguments               │
│  ├── get_network_connections(image_path) → network data              │
│  ├── scan_for_malware(image_path) → injection findings               │
│  ├── get_services(image_path) → service list                        │
│  ├── get_image_info(image_path) → OS metadata                       │
│  ├── verify_evidence(image_path) → SHA256 hash                      │
│  ├── list_files(image_path, search) → file listing                  │
│  ├── validate_findings(findings, image_path) → consistency check    │
│  └── get_system_info() → workstation details                        │
│                                                                     │
│  NOT EXPOSED (agent CANNOT call):                                   │
│  ✗ execute_shell_cmd()    — no raw shell access                     │
│  ✗ rm / dd / format       — no destructive commands                 │
│  ✗ wget / curl / ssh      — no data exfiltration                   │
│  ✗ write to /cases/       — no evidence modification                │
│  ✗ mount / umount         — no filesystem changes                   │
│                                                                     │
│  SAFETY MEASURES:                                                   │
│  • Input validation: os.path.exists() before every tool execution   │
│  • Output parsing: raw tool output parsed to structured data        │
│  • Error handling: graceful failure with informative messages        │
│  • Timeout: 120-300 second caps on all tool executions              │
│  • Evidence integrity: read-only access enforced                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    subprocess.run() with capture_output
                           │
┌──────────────────────────┴──────────────────────────────────────────┐
│                        TRUST BOUNDARY 3                              │
│                    (Forensic Tool Layer)                              │
│                                                                       │
│  Volatility 3          — Memory analysis (pslist, pstree, netscan)    │
│  Sleuth Kit (fls)      — Disk image file listing                      │
│  sha256sum             — Evidence integrity verification              │
│                                                                       │
│  All tools run with:                                                  │
│  • capture_output=True (output captured, not displayed)               │
│  • text=True (string output, not bytes)                               │
│  • timeout=120-300s (prevents hanging)                                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    Read-Only Access
                           │
┌──────────────────────────┴──────────────────────────────────────────┐
│                        EVIDENCE LAYER                                │
│                    (Immutable, Read-Only)                             │
│                                                                       │
│  Memory Images: .raw, .img files                                      │
│  Disk Images: .E01 files                                              │
│  NO writes to evidence directories                                    │
│  SHA256 hash computed for chain of custody                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Boundary Summary

| Boundary | Enforcement Type | What It Prevents |
|----------|-----------------|-----------------|
| Trust Boundary 1 | LangGraph state machine | Infinite loops (max 3 self-corrections), structured workflow |
| Trust Boundary 2 | Architectural (MCP Server) | Raw shell access, destructive commands, evidence modification |
| Trust Boundary 3 | subprocess controls | Runaway processes (timeouts), output capture |
| Evidence Layer | Read-only access | Evidence tampering, chain of custody violation |

## Architectural Pattern
This project uses **Architectural Pattern #2: Custom MCP Server** from the hackathon guidelines. Security is enforced by the server's API surface, not by prompt instructions.
