# Accuracy Report

## Self-Assessment of Agent Findings — Rocba Memory Image

### Methodology

The agent was run against the Rocba-Memory.raw (17.74 GB) memory image. After the automated investigation completed, the findings were manually reviewed by comparing:
1. Each claim in the agent's report against the raw Volatility tool output
2. PIDs mentioned in findings against the actual process list
3. Characterization of processes (suspicious vs normal) against known Windows behavior

### Evidence Integrity

| Check | Result |
|-------|--------|
| SHA256 hash computed | ✅ eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563 |
| Hash consistent across runs | ✅ Verified |
| Evidence modified | ✅ No — read-only access enforced by MCP server |

---

### Hallucinations Identified and Documented

**Hallucination 1: Tool name fabrication**
The LLM referenced "tasklist.exe output" in the report. We used Volatility 3 (`windows.pslist`), not `tasklist.exe`. The LLM substituted a more familiar Windows tool name.
- **Impact**: Low (finding is correct, tool attribution is wrong)
- **Root cause**: LLM training data associates process listing with tasklist.exe
- **Mitigation**: Future versions should include tool name in the structured output so the LLM cannot substitute

**Hallucination 2: "Screenshot attached"**
The report references "screenshot attached" multiple times. No screenshots were generated.
- **Impact**: Low (cosmetic, but reduces report credibility)
- **Root cause**: LLM pattern-matching on forensic report templates from training data
- **Mitigation**: Post-processing step to strip unverifiable references

**Hallucination 3: Normal processes flagged as suspicious**
The agent flagged Slack.exe (PID 1152) and Chrome.exe (PID 5532) running under explorer.exe (PID 7464) as "suspicious." This is completely normal — explorer.exe is the Windows shell, and all user-launched applications run under it.
- **Impact**: High (false positive, would mislead an analyst)
- **Root cause**: LLM lacks deep Windows process hierarchy knowledge
- **Mitigation**: Add process baseline whitelist to the MCP server's validate_findings tool

**Hallucination 4: Multiple svchost.exe flagged as malware**
The agent flagged the presence of many svchost.exe instances as a "malware indicator." Windows 10 normally runs 60-80+ svchost.exe instances — this is expected behavior, not suspicious.
- **Impact**: High (false positive, fundamental misunderstanding of Windows)
- **Root cause**: LLM training data includes CTF-style analysis where multiple svchost is suspicious
- **Mitigation**: Add Windows process count baselines to the validation tool

---

### Findings the Agent Missed

**Missed Finding 1: MRC.exe (PID 29440) from D:\Tools\**
The most suspicious process in the entire image — a program named MRC.exe running from `D:\Tools\MRC.exe`. MRC likely stands for a remote access tool. Running from a Tools folder on a D: drive is highly unusual for a corporate Surface laptop. Our manual grep analysis found this, but the LLM did not highlight it in its analysis despite the data being present in the tool output.
- **Impact**: Critical — this is likely the primary IOC
- **Root cause**: The process list was truncated to 3000 characters before sending to the LLM. MRC.exe was near the end of the list (PID 29440) and was cut off.
- **Mitigation**: Implement a pre-filtering step that surfaces high-entropy or unusual process names before truncation

**Missed Finding 2: Abnormal number of Teams.exe processes**
Approximately 1000+ Teams.exe processes were running, most with no command line arguments. Normal Teams has 5-15 processes. This extreme count warrants investigation.
- **Impact**: Medium — could indicate process injection, memory leak, or masquerading
- **Root cause**: Same truncation issue — the volume of Teams processes dominated the data
- **Mitigation**: Add process count anomaly detection to the MCP server

**Missed Finding 3: Three simultaneous cloud sync services**
OneDrive, Google Drive, and iCloud were all running — three potential data exfiltration paths. The agent noted some of these in raw findings but did not highlight the significance for the IP theft investigation.
- **Impact**: Medium — directly relevant to "where was data transferred"
- **Root cause**: LLM did not connect cloud sync services to the data exfiltration question
- **Mitigation**: Add case-context awareness to the agent prompts

---

### True Positive Findings

| Finding | Verified |
|---------|----------|
| Windows 10, build 19041, 64-bit | ✅ Confirmed by windows.info |
| 4 processors | ✅ Confirmed by windows.info |
| System time 2020-11-16 02:32:38 UTC | ✅ Confirmed by windows.info |
| 2186 processes found | ✅ Confirmed by windows.pslist |
| explorer.exe PID 7464 present | ✅ Confirmed by windows.pslist |
| Evidence hash computed correctly | ✅ Confirmed by sha256sum |

---

### Self-Correction Effectiveness

The agent performed 3 self-correction rounds:

| Round | Action | Result |
|-------|--------|--------|
| 1 | Validated PIDs against process list | Found gaps in coverage, looped back |
| 2 | Re-analyzed with additional context | Found more gaps, looped back |
| 3 | Final validation | Max iterations reached, generated report |

The self-correction caught that network analysis and command-line analysis were mentioned as gaps. However, these tools WERE executed — the self-correction failed to recognize that the data was already collected. This is an LLM reasoning error, not a tool error.

---

### False Positive Rate

| Category | Count | Examples |
|----------|-------|---------|
| Processes incorrectly flagged suspicious | 3 | Slack.exe, Chrome.exe, svchost.exe instances |
| Tool name hallucinations | 1 | "tasklist.exe" instead of Volatility |
| Non-existent references | 1 | "screenshot attached" |
| **Total false positives** | **5** | |

### False Negative Rate

| Category | Count | Examples |
|----------|-------|---------|
| Suspicious processes missed | 1 | MRC.exe from D:\Tools\ |
| Anomalies missed | 1 | 1000+ Teams.exe processes |
| Context-relevant findings missed | 1 | Three cloud sync services as exfil paths |
| **Total false negatives** | **3** | |

---

### Evidence Integrity Approach

**Architectural enforcement (not prompt-based):**
1. The MCP server validates that `image_path` exists via `os.path.exists()` before every tool execution
2. Volatility is invoked with read-only flags — no write operations are possible through the exposed tools
3. The server does not expose `mount`, `umount`, `dd`, `rm`, or any filesystem-modifying commands
4. Evidence hash (SHA256) is computed at the start of every investigation for chain of custody

**Tested for bypass?**
The MCP server does not expose `execute_shell_cmd` or any equivalent. An AI agent connected to this server literally cannot construct a command that modifies evidence — the function does not exist. This is architectural enforcement, not prompt-based restriction.

---

### Limitations and Honest Assessment

1. **Token limits**: Free-tier LLM rate limits forced aggressive truncation of tool output, causing the agent to miss findings that were present in the raw data
2. **Windows domain knowledge**: The LLM lacks deep understanding of normal vs abnormal Windows process hierarchies, leading to false positives
3. **Single-source analysis**: Only memory analysis was performed; disk image analysis would provide corroborating evidence
4. **LLM reasoning**: The self-correction mechanism caught structural gaps but failed to catch content-level errors (flagging normal processes as suspicious)
5. **No ground truth**: The Rocba case does not have a published answer key, so we cannot compute precision/recall against known findings

### What We Would Improve

1. Add a Windows process baseline whitelist to the MCP server
2. Implement pre-truncation anomaly detection (surface unusual processes before cutting data)
3. Add process count analysis (flag when a process name appears >20 times)
4. Use a larger context window LLM to avoid truncation-related misses
5. Add disk image correlation to cross-reference memory findings
