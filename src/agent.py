import os
import json
import time
from datetime import datetime, timezone
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

# Import our MCP tools
import sys
sys.path.insert(0, os.path.dirname(__file__))
from server import (
    get_system_info,
    get_process_list,
    get_network_connections,
    scan_for_malware,
    get_process_tree,
    get_command_lines,
    get_services,
    verify_evidence,
    get_image_info,
    validate_findings
)


# ── Agent State ──────────────────────────────────────────────
class ForensicState(TypedDict):
    image_path: str
    findings: dict
    execution_log: list
    current_step: str
    analysis_complete: bool
    self_correction_count: int
    final_report: str


# ── Logging Helper ───────────────────────────────────────────
def log_execution(state: ForensicState, tool_name: str, tool_input: str, tool_output: str) -> None:
    """Log every tool execution with timestamp for audit trail."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "step": state["current_step"],
        "tool": tool_name,
        "input": tool_input,
        "output_preview": tool_output[:500],
        "output_full": tool_output
    }
    state["execution_log"].append(entry)


# ── LLM Setup ───────────────────────────────────────────────
# def get_llm():
#     return ChatGoogleGenerativeAI(
#         model="gemini-2.0-flash",
#         google_api_key=os.environ.get("GEMINI_API_KEY"),
#         temperature=0.1
#     )

def get_llm():
    from langchain_groq import ChatGroq
    return ChatGroq(
        model="llama-3.1-8b-instant",
        api_key=os.environ.get("GROQ_API_KEY"),
        temperature=0.1
    )

# ── Node 1: Initial Triage ──────────────────────────────────
def triage_node(state: ForensicState) -> ForensicState:
    """Run initial triage: system info, process list, image info."""
    state["current_step"] = "triage"
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] Starting triage...")

    # Tool 1: System info
    result = get_system_info()
    log_execution(state, "get_system_info", "", result)
    state["findings"]["system_info"] = result
    print(f"  System info collected")

    # Tool 2: Image info
    result = get_image_info(state["image_path"])
    log_execution(state, "get_image_info", state["image_path"], result)
    state["findings"]["image_info"] = result
    print(f"  Image info collected")

    # Tool 3: Process list
    result = get_process_list(state["image_path"])
    log_execution(state, "get_process_list", state["image_path"], result)
    state["findings"]["process_list"] = result
    print(f"  Process list collected")

    # Tool 4: Process tree
    result = get_process_tree(state["image_path"])
    log_execution(state, "get_process_tree", state["image_path"], result)
    state["findings"]["process_tree"] = result
    print(f"  Process tree collected")

    return state


# ── Node 2: Deep Analysis ───────────────────────────────────
def deep_analysis_node(state: ForensicState) -> ForensicState:
    """Deep dive: network, commands, services, malware scan."""
    state["current_step"] = "deep_analysis"
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] Starting deep analysis...")

    # Tool 5: Network connections
    result = get_network_connections(state["image_path"])
    log_execution(state, "get_network_connections", state["image_path"], result)
    state["findings"]["network_connections"] = result
    print(f"  Network connections collected")

    # Tool 6: Command lines
    result = get_command_lines(state["image_path"])
    log_execution(state, "get_command_lines", state["image_path"], result)
    state["findings"]["command_lines"] = result
    print(f"  Command lines collected")

    # Tool 7: Services
    result = get_services(state["image_path"])
    log_execution(state, "get_services", state["image_path"], result)
    state["findings"]["services"] = result
    print(f"  Services collected")

    # Tool 8: Malware scan
    result = scan_for_malware(state["image_path"])
    log_execution(state, "scan_for_malware", state["image_path"], result)
    state["findings"]["malware_scan"] = result
    print(f"  Malware scan completed")

    return state


# ── Node 3: AI Analysis ─────────────────────────────────────
def ai_analysis_node(state: ForensicState) -> ForensicState:
    """Use Gemini to analyze findings and identify anomalies."""
    state["current_step"] = "ai_analysis"
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] AI analyzing findings...")

    llm = get_llm()

    findings_text = json.dumps(state["findings"], indent=2)

    prompt = f"""You are a senior digital forensics analyst. Analyze these forensic findings 
from a memory image and identify:

1. CONFIRMED suspicious processes (with evidence)
2. CONFIRMED suspicious network connections (with evidence)
3. CONFIRMED malware indicators (with evidence)
4. Any gaps in the analysis that need further investigation
5. Logical inconsistencies in the findings

Be PRECISE. Only report findings that are directly supported by the tool output below.
Clearly label each finding as CONFIRMED (directly from tool output) or INFERRED (your analysis).
If something looks suspicious but you cannot confirm it, say so explicitly.

DO NOT fabricate any PIDs, file paths, or network addresses that are not in the data below.

FINDINGS:
{findings_text[:8000]}

Respond in this exact format:
CONFIRMED FINDINGS:
- [finding with specific evidence]

INFERRED FINDINGS:
- [inference with reasoning]

GAPS IDENTIFIED:
- [what needs more investigation]

RISK ASSESSMENT:
[overall assessment]"""

    response = llm.invoke([HumanMessage(content=prompt)])
    analysis = response.content

    log_execution(state, "gemini_analysis", "Full findings analysis", analysis)
    state["findings"]["ai_analysis"] = analysis
    print(f"  AI analysis complete")

    return state


# ── Node 4: Self-Correction ─────────────────────────────────
def self_correction_node(state: ForensicState) -> ForensicState:
    """Validate findings and self-correct if issues found."""
    state["current_step"] = "self_correction"
    state["self_correction_count"] += 1
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] Self-correction round {state['self_correction_count']}...")

    # Use our validate_findings tool
    ai_analysis = state["findings"].get("ai_analysis", "")
    validation = validate_findings(ai_analysis, state["image_path"])
    log_execution(state, "validate_findings", "Validating AI analysis", validation)
    state["findings"]["validation"] = validation
    print(f"  Validation complete")

    # Use Gemini to evaluate the validation
    llm = get_llm()

    prompt = f"""You are a forensic quality reviewer. Review this validation report and the 
original analysis. Identify:

1. Any findings that failed validation (mentioned PIDs that don't exist, etc.)
2. Analysis gaps that should be investigated
3. Whether the analysis is ready for final reporting

ORIGINAL ANALYSIS:
{ai_analysis[:4000]}

VALIDATION REPORT:
{validation}

Respond with:
CORRECTIONS NEEDED:
- [specific correction]

ADDITIONAL INVESTIGATION NEEDED:
- [what to check] or NONE

READY FOR REPORT: YES or NO"""

    response = llm.invoke([HumanMessage(content=prompt)])
    correction_analysis = response.content

    log_execution(state, "gemini_self_correction", "Evaluating validation", correction_analysis)
    state["findings"]["correction_analysis"] = correction_analysis
    print(f"  Correction analysis complete")

    if "READY FOR REPORT: YES" in correction_analysis.upper() or state["self_correction_count"] >= 3:
        state["analysis_complete"] = True
    else:
        state["analysis_complete"] = False

    return state


# ── Node 5: Generate Report ─────────────────────────────────
def report_node(state: ForensicState) -> ForensicState:
    """Generate final structured forensic report."""
    state["current_step"] = "reporting"
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] Generating final report...")

    llm = get_llm()

    prompt = f"""Generate a structured forensic investigation report.

CRITICAL RULES:
- Only include findings directly supported by tool output
- Label each finding as CONFIRMED or INFERRED
- Document any errors caught during self-correction
- Be honest about limitations and gaps

AI ANALYSIS:
{state["findings"].get("ai_analysis", "No analysis")[:2000]}

VALIDATION:
{state["findings"].get("validation", "No validation")[:500]}

EVIDENCE INTEGRITY:
{state["findings"].get("evidence_integrity", "Not computed")}

Format the report as:
# Forensic Investigation Report
## Case: Memory Analysis
## Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

### Executive Summary
[brief overview]

### Confirmed Findings
[each finding with tool evidence]

### Inferred Findings  
[each inference with reasoning]

### Self-Correction Log
[errors caught and corrected]

### Analysis Gaps
[what was not covered and why]

### Evidence Integrity
[hash verification results]

### Recommendations
[next steps]"""

    response = llm.invoke([HumanMessage(content=prompt)])
    state["final_report"] = response.content

    log_execution(state, "gemini_report_generation", "Final report", state["final_report"])
    print(f"  Report generated")

    return state


# ── Routing Logic ────────────────────────────────────────────
def should_self_correct(state: ForensicState) -> str:
    """Decide whether to self-correct again or generate report."""
    if state["analysis_complete"]:
        return "report"
    else:
        return "deep_analysis"


# ── Build the Graph ──────────────────────────────────────────
def build_agent():
    """Build the LangGraph forensic investigation agent."""
    graph = StateGraph(ForensicState)

    # Add nodes
    graph.add_node("triage", triage_node)
    graph.add_node("deep_analysis", deep_analysis_node)
    graph.add_node("ai_analysis", ai_analysis_node)
    graph.add_node("self_correction", self_correction_node)
    graph.add_node("report", report_node)

    # Add edges
    graph.set_entry_point("triage")
    graph.add_edge("triage", "deep_analysis")
    graph.add_edge("deep_analysis", "ai_analysis")
    graph.add_edge("ai_analysis", "self_correction")
    graph.add_conditional_edges(
        "self_correction",
        should_self_correct,
        {"report": "report", "deep_analysis": "deep_analysis"}
    )
    graph.add_edge("report", END)

    return graph.compile()


# ── Main Entry Point ─────────────────────────────────────────
def run_investigation(image_path: str) -> dict:
    """Run a full forensic investigation on the given memory image."""
    print(f"{'='*60}")
    print(f"SIFT MCP Forensic Investigation Agent")
    print(f"Image: {image_path}")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    # Verify evidence first
    integrity = verify_evidence(image_path)
    print(f"\nEvidence Integrity:\n{integrity}")

    # Initial state
    initial_state = {
        "image_path": image_path,
        "findings": {"evidence_integrity": integrity},
        "execution_log": [],
        "current_step": "init",
        "analysis_complete": False,
        "self_correction_count": 0,
        "final_report": ""
    }

    # Run the agent
    agent = build_agent()
    final_state = agent.invoke(initial_state)

    # Save execution logs
    log_dir = os.path.expanduser("~/sift-mcp-server/submission/execution_logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    with open(f"{log_dir}/execution_log_{timestamp}.json", "w") as f:
        json.dump(final_state["execution_log"], f, indent=2)

    with open(f"{log_dir}/final_report_{timestamp}.md", "w") as f:
        f.write(final_state["final_report"])

    print(f"\n{'='*60}")
    print(f"Investigation Complete")
    print(f"Execution log: {log_dir}/execution_log_{timestamp}.json")
    print(f"Final report: {log_dir}/final_report_{timestamp}.md")
    print(f"Self-corrections: {final_state['self_correction_count']}")
    print(f"Total tool executions: {len(final_state['execution_log'])}")
    print(f"{'='*60}")

    return final_state


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python agent.py <path-to-memory-image>")
        sys.exit(1)

    image_path = sys.argv[1]
    run_investigation(image_path)