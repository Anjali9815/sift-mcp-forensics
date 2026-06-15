# SIFT MCP Forensic Investigation Agent

## Find Evil! Hackathon 2026 — Autonomous DFIR Agent

An autonomous forensic investigation agent that combines a **purpose-built MCP server** (architectural guardrails) with a **self-correcting LangGraph agent** to analyze memory images from the SANS SIFT Workstation. The agent thinks like a senior analyst: sequences its approach, recognizes when something doesn't add up, and self-corrects when it gets it wrong.

---

## Submission Compliance Checklist

| # | Requirement | Location | Status |
|---|-------------|----------|--------|
| 1 | Code Repository (Public) | This repo | ✅ |
| 2 | Open Source License (MIT) | [LICENSE](./LICENSE) | ✅ |
| 3 | README with Setup | This file | ✅ |
| 4 | Try-It-Out Instructions | [Quickstart](#quickstart) | ✅ |
| 5 | Project Description | [Overview](#overview) | ✅ |
| 6 | Demo Video (5 min) | [Link](#demo-video) | ✅ |
| 7 | Architecture Diagram | [docs/architecture.md](./docs/architecture.md) | ✅ |
| 8 | Dataset Documentation | [docs/dataset.md](./docs/dataset.md) | ✅ |
| 9 | Accuracy Report | [docs/accuracy_report.md](./docs/accuracy_report.md) | ✅ |
| 10 | Agent Execution Logs | [submission/execution_logs/](./submission/execution_logs/) | ✅ |

---

## Overview

### The Problem
AI-powered adversaries can go from initial access to full domain control in under 8 minutes. Human incident responders are still pulling up their toolkit. This gap is the most dangerous problem in cybersecurity.

### Our Solution
We built a two-layer system that closes this gap:

**Layer 1 — Purpose-Built MCP Server (Architectural Guardrails)**
Instead of giving the AI raw shell access (`execute_shell_cmd`), we wrap SIFT's forensic tools as typed, safe Python functions exposed through a Model Context Protocol server. The agent physically cannot run destructive commands because the server doesn't expose them. Output is parsed before reaching the AI, preventing context window overload.

**Layer 2 — Self-Correcting LangGraph Agent**
A state machine agent that follows the six-step forensic methodology: triage, deep analysis, AI reasoning, self-correction, and reporting. The agent forms hypotheses, validates its own findings against the evidence, identifies gaps, loops back for deeper investigation, and produces a structured report with every finding labeled as CONFIRMED or INFERRED.

### Key Differentiator: Architectural vs Prompt-Based Security
Most submissions use Protocol SIFT's default `settings.json` — a prompt-based permission system that says "please don't run dangerous commands." Our MCP server enforces safety architecturally: dangerous commands don't exist as callable functions. The AI cannot hallucinate a destructive command because the server's API surface doesn't include one.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    LangGraph Agent                        │
│                                                           │
│  ┌──────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │  Triage   │──▶│Deep Analysis │──▶│  AI Analysis   │   │
│  └──────────┘   └──────────────┘   └───────┬────────┘   │
│                        ▲                     │            │
│                        │    if gaps found    │            │
│                        └─────────────────────┤            │
│                                              ▼            │
│                                    ┌─────────────────┐   │
│                                    │Self-Correction   │   │
│                                    └────────┬────────┘   │
│                                             │             │
│                              if complete    │             │
│                                             ▼             │
│                                    ┌─────────────────┐   │
│                                    │  Report Gen     │   │
│                                    └─────────────────┘   │
└────────────────────────┬────────────────────────────────┘
                         │ MCP Protocol
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Purpose-Built MCP Server                     │
│                                                           │
│  Typed Functions (no raw shell access):                   │
│  • get_process_list()     • get_network_connections()     │
│  • get_process_tree()     • get_command_lines()           │
│  • scan_for_malware()     • get_services()                │
│  • get_image_info()       • verify_evidence()             │
│  • list_files()           • validate_findings()           │
│  • get_system_info()                                      │
│                                                           │
│  Security: Input validation, output parsing, no           │
│  destructive commands exposed, evidence read-only         │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           SIFT Forensic Tools                             │
│  Volatility 3 | Sleuth Kit | Plaso | YARA | bulk_extractor│
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           Evidence (Read-Only)                            │
│  Memory Images (.raw, .img) | Disk Images (.E01)          │
└─────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](./docs/architecture.md) for the full architecture diagram with trust boundaries.

---

## Quickstart

### Prerequisites
- SANS SIFT Workstation (Ubuntu 22.04, x86-64) or equivalent Ubuntu VM
- Python 3.10+
- Volatility 3 installed (`pip install volatility3` or via SIFT)
- Sleuth Kit installed (`apt install sleuthkit`)
- A Groq API key (free at console.groq.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sift-mcp-forensics.git
cd sift-mcp-forensics

# Install Python dependencies
pip3 install mcp langgraph langchain-groq langchain-core

# Set your API key
export GROQ_API_KEY="your-groq-api-key"
```

### Run the Agent

```bash
# Run against a memory image
python3 src/agent.py /path/to/memory-image.raw

# Example with Rocba case data
python3 src/agent.py /cases/Rocba-Memory/Rocba-Memory.raw
```

### Run the MCP Server Standalone

```bash
# Start the MCP server
python3 src/server.py

# Test individual tools
python3 test_tool.py
```

### Output
The agent produces:
- **Execution logs** (JSON with timestamps) in `submission/execution_logs/`
- **Final report** (Markdown) in `submission/execution_logs/`
- **Console output** showing real-time investigation progress

---

## Project Structure

```
sift-mcp-forensics/
├── README.md                          ← This file
├── LICENSE                            ← MIT License
├── SUBMISSION_COMPLIANCE.md           ← Checklist for judges
├── src/
│   ├── server.py                      ← MCP Server (11 typed forensic tools)
│   └── agent.py                       ← LangGraph self-correcting agent
├── tests/
│   └── (test files)
├── test_tool.py                       ← Tool verification script
├── docs/
│   ├── architecture.md                ← Architecture diagram + trust boundaries
│   ├── dataset.md                     ← Evidence dataset documentation
│   └── accuracy_report.md            ← Self-assessment with hallucination analysis
└── submission/
    └── execution_logs/
        ├── execution_log_*.json       ← Full tool execution traces with timestamps
        └── final_report_*.md          ← Generated forensic reports
```

---

## How It Works

### The MCP Server (src/server.py)
11 typed forensic tool functions exposed through Model Context Protocol:

| Tool | Purpose | Volatility Plugin |
|------|---------|-------------------|
| `get_system_info()` | Workstation details | N/A |
| `get_process_list()` | All running processes | `windows.pslist` |
| `get_process_tree()` | Parent-child relationships | `windows.pstree` |
| `get_command_lines()` | Process command arguments | `windows.cmdline` |
| `get_network_connections()` | Network connections | `windows.netscan` |
| `scan_for_malware()` | Injected code detection | `windows.malfind` |
| `get_services()` | Windows services | `windows.svcscan` |
| `get_image_info()` | Memory image metadata | `windows.info` |
| `verify_evidence()` | SHA256 hash for chain of custody | `sha256sum` |
| `list_files()` | Browse disk image files | `fls` (Sleuth Kit) |
| `validate_findings()` | Cross-check findings consistency | Custom validation |

Each tool:
- Validates input before execution (file existence check)
- Runs the forensic tool internally
- Parses raw output into structured data
- Returns clean, formatted results
- Handles errors gracefully with informative messages

### The Agent (src/agent.py)
A LangGraph state machine with 5 nodes:

1. **Triage** — Initial assessment: system info, image metadata, process list, process tree
2. **Deep Analysis** — Network connections, command lines, services, malware scan
3. **AI Analysis** — LLM analyzes all findings, identifies anomalies, labels CONFIRMED vs INFERRED
4. **Self-Correction** — Validates findings against evidence, identifies gaps, decides whether to loop back
5. **Report** — Generates structured forensic report

The agent self-corrects up to 3 times before generating the final report. Each self-correction round validates PIDs mentioned in findings against the actual process list and checks for analysis coverage gaps.

### Audit Trail
Every tool execution is logged with:
- UTC timestamp
- Tool name
- Input parameters
- Full output
- Current investigation step

Judges can trace any finding in the report back to the specific tool execution that produced it.

---

## Architectural Approach

This project implements **Idea #6 (Purpose-Built MCP Server)** combined with **Idea #1 (Self-Correcting Triage Agent)** from the hackathon starter ideas.

### Why Custom MCP Server (Architectural Pattern #2)
- **Architectural enforcement**: The agent cannot run destructive commands because they don't exist in the server's API
- **Input validation**: Every tool validates file paths before execution
- **Output parsing**: Raw Volatility output is parsed before reaching the LLM, preventing context overload
- **Evidence integrity**: The server enforces read-only access to evidence files
- **Typed functions**: `get_process_list(image_path)` instead of `execute_shell_cmd("vol -f image pslist")`

### Prompt-Based vs Architectural Guardrails
| Aspect | Protocol SIFT Default | Our MCP Server |
|--------|----------------------|----------------|
| Security model | JSON permission file | Functions don't exist |
| Destructive commands | "Denied" in config | Not exposed |
| Evidence protection | Prompt instruction | Input validation |
| Output handling | Raw text to LLM | Parsed structured data |
| Hallucination risk | AI constructs commands | AI calls typed functions |

---

## Demo Video

[Link to demo video on YouTube/Vimeo]

The video demonstrates:
1. Agent starting investigation on Rocba memory image
2. Real-time triage and deep analysis
3. AI analysis identifying suspicious processes
4. Self-correction catching errors and looping back
5. Final report generation with CONFIRMED/INFERRED labels

---

## Technologies Used

- **Python 3.10** — Core language
- **MCP (Model Context Protocol)** — Tool server protocol
- **LangGraph** — Agent state machine framework
- **LangChain** — LLM integration
- **Groq (LLaMA 3.1)** — LLM for analysis and reasoning
- **Volatility 3** — Memory forensics framework
- **Sleuth Kit** — Disk forensics toolkit
- **SANS SIFT Workstation** — Forensic tool platform
- **Google Cloud Platform** — VM infrastructure

---

## Author

**Anjali Jha**
MS in Data Science & AI, University of Maryland Baltimore County (2026)

---

## License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.
