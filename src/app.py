import streamlit as st
import json
import os
import time
import subprocess
from datetime import datetime, timezone

# Page config
st.set_page_config(
    page_title="SIFT MCP Forensic Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for hacker theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');
    
    .stApp {
        background-color: #0a0e17;
        color: #c9d1d9;
    }
    
    .main-header {
        font-family: 'JetBrains Mono', monospace;
        color: #00ff41;
        font-size: 2.2rem;
        text-align: center;
        padding: 20px 0;
        text-shadow: 0 0 10px #00ff4155;
        border-bottom: 1px solid #00ff4133;
        margin-bottom: 20px;
    }
    
    .sub-header {
        font-family: 'JetBrains Mono', monospace;
        color: #00ff41;
        font-size: 1.1rem;
        text-align: center;
        opacity: 0.7;
        margin-top: -15px;
        margin-bottom: 30px;
    }
    
    .status-box {
        background: #111827;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
    }
    
    .finding-confirmed {
        background: #0d2818;
        border-left: 3px solid #00ff41;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 0 6px 6px 0;
        font-family: 'Inter', sans-serif;
    }
    
    .finding-inferred {
        background: #1a1a2e;
        border-left: 3px solid #e6b800;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 0 6px 6px 0;
        font-family: 'Inter', sans-serif;
    }
    
    .finding-suspicious {
        background: #2d1117;
        border-left: 3px solid #ff4444;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 0 6px 6px 0;
        font-family: 'Inter', sans-serif;
    }
    
    .metric-card {
        background: #111827;
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2rem;
        color: #00ff41;
        text-shadow: 0 0 8px #00ff4133;
    }
    
    .metric-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #8b949e;
        margin-top: 5px;
    }
    
    .tool-badge {
        display: inline-block;
        background: #1e3a5f;
        color: #58a6ff;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        margin: 2px;
    }
    
    .log-entry {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #8b949e;
        padding: 4px 0;
        border-bottom: 1px solid #1e3a5f22;
    }
    
    .log-timestamp {
        color: #00ff41;
    }
    
    .log-tool {
        color: #58a6ff;
    }
    
    div[data-testid="stSidebar"] {
        background-color: #0d1117;
        border-right: 1px solid #1e3a5f;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%);
        color: #0a0e17;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        border: none;
        padding: 12px 30px;
        font-size: 1rem;
        border-radius: 6px;
        width: 100%;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #33ff66 0%, #00ff41 100%);
        box-shadow: 0 0 15px #00ff4144;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">🔍 SIFT MCP FORENSIC AGENT</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Autonomous incident response powered by architectural guardrails</div>', unsafe_allow_html=True)


# Intro slides
if 'slide' not in st.session_state:
    st.session_state.slide = 0

slides = [
    {
        "icon": "🎯",
        "title": "The Problem",
        "text": "AI attackers breach systems in under 8 minutes. Human defenders still look up command-line flags. The gap is lethal."
    },
    {
        "icon": "🛡️",
        "title": "Our Solution", 
        "text": "A purpose-built MCP server wrapping 200+ SIFT tools as typed safe functions. The AI cannot run destructive commands — they don't exist."
    },
    {
        "icon": "🔄",
        "title": "Self-Correction",
        "text": "A LangGraph agent that investigates, validates its own findings against evidence, catches errors, and loops back to dig deeper."
    },
    {
        "icon": "🏗️",
        "title": "Architectural Guardrails",
        "text": "Not prompt-based. No 'please don't delete evidence.' Functions physically don't exist. Safety by design, not by asking nicely."
    },
    {
        "icon": "📊",
        "title": "Honest About Failures",
        "text": "We document every hallucination the AI made. Caught errors count FOR us. Honesty over perfection — exactly what DFIR demands."
    }
]

col_prev, col_slide, col_next = st.columns([1, 8, 1])

with col_prev:
    if st.button("◀", key="prev"):
        st.session_state.slide = (st.session_state.slide - 1) % len(slides)

with col_next:
    if st.button("▶", key="next"):
        st.session_state.slide = (st.session_state.slide + 1) % len(slides)

slide = slides[st.session_state.slide]

with col_slide:
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); 
                border: 1px solid #1e3a5f; border-radius: 12px; padding: 30px; 
                text-align: center; min-height: 120px;">
        <div style="font-size: 2.5rem; margin-bottom: 10px;">{slide["icon"]}</div>
        <div style="font-family: 'JetBrains Mono', monospace; color: #00ff41; 
                    font-size: 1.3rem; margin-bottom: 10px;">{slide["title"]}</div>
        <div style="font-family: 'Inter', sans-serif; color: #c9d1d9; 
                    font-size: 1rem; line-height: 1.6;">{slide["text"]}</div>
        <div style="margin-top: 15px; opacity: 0.4; font-size: 0.8rem;">
            {st.session_state.slide + 1} / {len(slides)}
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("")


# Sidebar
with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    
    image_path = st.text_input(
        "Memory Image Path",
        value="/home/vijayshankarmishra/sample-evidence/Rocba-Memory/Rocba-Memory.raw",
        help="Path to the memory image file (.raw or .img)"
    )
    
    api_key = st.text_input("Groq API Key", type="password", value=os.environ.get("GROQ_API_KEY", ""))
    
    st.markdown("---")
    st.markdown("### 🛡️ Architecture")
    st.markdown("""
    <div class="status-box">
    <strong style="color:#00ff41">Architectural Guardrails</strong><br>
    ✅ Typed MCP functions only<br>
    ✅ No raw shell access<br>
    ✅ Input validation on every call<br>
    ✅ Output parsed before LLM<br>
    ✅ Evidence read-only enforced<br>
    ❌ No rm/dd/wget/curl/ssh
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🔧 MCP Tools (11)")
    tools = [
        "get_system_info", "get_process_list", "get_process_tree",
        "get_command_lines", "get_network_connections", "scan_for_malware",
        "get_services", "get_image_info", "verify_evidence",
        "list_files", "validate_findings"
    ]
    for tool in tools:
        st.markdown(f'<span class="tool-badge">{tool}</span>', unsafe_allow_html=True)

# Main content
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Investigation", "📊 Findings", "📋 Execution Logs", "📄 Report"])

with tab1:
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">11</div>
            <div class="metric-label">MCP Tools</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">5</div>
            <div class="metric-label">Agent Nodes</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">3</div>
            <div class="metric-label">Max Corrections</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">0</div>
            <div class="metric-label">Shell Commands</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    if st.button("🚀 START INVESTIGATION", use_container_width=True):
        if not api_key:
            st.error("Please enter your Groq API key in the sidebar")
        elif not os.path.exists(image_path):
            st.error(f"File not found: {image_path}")
        else:
            os.environ["GROQ_API_KEY"] = api_key
            
            progress = st.progress(0, text="Initializing investigation...")
            log_area = st.empty()
            
            steps = [
                ("Computing SHA256 hash...", 10),
                ("Running triage: system info, processes...", 25),
                ("Deep analysis: network, services, malware...", 50),
                ("AI analyzing findings...", 70),
                ("Self-correction round 1...", 80),
                ("Self-correction round 2...", 88),
                ("Generating final report...", 95),
            ]
            
            # Run the actual agent
            log_area.markdown('<div class="status-box">🔄 Starting agent...</div>', unsafe_allow_html=True)
            
            process = subprocess.Popen(
                ["python3", "src/agent.py", image_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.expanduser("~/sift-mcp-server"),
                env={**os.environ, "GROQ_API_KEY": api_key}
            )
            
            output_lines = []
            step_idx = 0
            
            for line in process.stdout:
                output_lines.append(line.strip())
                
                # Update progress based on output
                if "Starting triage" in line and step_idx < 1:
                    step_idx = 1
                    progress.progress(25, text="🔍 Triage: collecting processes...")
                elif "Starting deep analysis" in line and step_idx < 2:
                    step_idx = 2
                    progress.progress(50, text="🔬 Deep analysis: network, malware...")
                elif "AI analyzing" in line and step_idx < 3:
                    step_idx = 3
                    progress.progress(70, text="🧠 AI analyzing findings...")
                elif "Self-correction round" in line:
                    step_idx += 1
                    round_num = line.split("round")[1].strip().replace("...", "").strip() if "round" in line else "?"
                    progress.progress(min(80 + step_idx * 5, 95), text=f"🔄 Self-correction round {round_num}...")
                elif "Generating final report" in line:
                    progress.progress(95, text="📝 Generating report...")
                elif "Investigation Complete" in line:
                    progress.progress(100, text="✅ Investigation complete!")
                
                # Show last 15 lines
                display_lines = output_lines[-15:]
                log_html = '<div class="status-box">'
                for l in display_lines:
                    if "[202" in l:
                        log_html += f'<span class="log-timestamp">{l}</span><br>'
                    elif "collected" in l or "completed" in l or "complete" in l:
                        log_html += f'<span class="log-tool">  {l}</span><br>'
                    else:
                        log_html += f'{l}<br>'
                log_html += '</div>'
                log_area.markdown(log_html, unsafe_allow_html=True)
            
            process.wait()
            
            if process.returncode == 0:
                st.success("Investigation complete! Check the Findings and Report tabs.")
                st.balloons()
            else:
                st.error("Agent encountered an error. Check logs for details.")
                st.code("\n".join(output_lines[-20:]))

with tab2:
    st.markdown("### 🔍 Key Findings from Rocba Case")
    
    st.markdown("""
    <div class="finding-suspicious">
        <strong>🚨 SUSPICIOUS: MRC.exe (PID 29440)</strong><br>
        Running from <code>D:\\Tools\\MRC.exe</code> — remote access tool from non-standard location on secondary drive. 
        Launched by explorer.exe. This is the primary IOC.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="finding-suspicious">
        <strong>🚨 ANOMALY: 1000+ Teams.exe processes</strong><br>
        Normal Microsoft Teams runs 5-15 processes. This system has ~1000+ Teams.exe instances, 
        most with no command line arguments. Warrants deep investigation.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="finding-confirmed">
        <strong>✅ CONFIRMED: Three cloud sync services active</strong><br>
        OneDrive (personal + business), Google Drive, and iCloud all running simultaneously.
        Three potential data exfiltration paths. Directly relevant to IP theft investigation.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="finding-confirmed">
        <strong>✅ CONFIRMED: System identification</strong><br>
        Windows 10 build 19041, 64-bit, 4 CPUs. User: fredr (Fred Rocba).
        Captured: 2020-11-16 02:32:38 UTC. Microsoft Surface laptop.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="finding-confirmed">
        <strong>✅ CONFIRMED: iCloud Photos syncing vacation photos</strong><br>
        ApplePhotoStreams.exe and iCloudPhotos.exe active — Disney vacation photos syncing 
        to this system while Fred was away. Confirms case timeline.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="finding-inferred">
        <strong>⚠️ INFERRED: Potential data exfiltration via cloud sync</strong><br>
        With three cloud services running and physical access to the machine, an intruder could 
        have synced sensitive SRL research files to an external cloud account.
    </div>
    """, unsafe_allow_html=True)

with tab3:
    st.markdown("### 📋 Execution Logs")
    
    log_dir = os.path.expanduser("~/sift-mcp-server/submission/execution_logs")
    
    if os.path.exists(log_dir):
        log_files = sorted([f for f in os.listdir(log_dir) if f.endswith('.json')])
        
        if log_files:
            selected_log = st.selectbox("Select log file", log_files)
            log_path = os.path.join(log_dir, selected_log)
            
            with open(log_path, 'r') as f:
                log_data = json.load(f)
            
            st.markdown(f"**Total tool executions:** {len(log_data)}")
            
            for i, entry in enumerate(log_data):
                timestamp = entry.get("timestamp", "N/A")
                tool = entry.get("tool", "unknown")
                step = entry.get("step", "unknown")
                preview = entry.get("output_preview", "")[:200]
                
                with st.expander(f"[{timestamp}] {tool} ({step})"):
                    st.markdown(f"""
                    <div class="log-entry">
                        <span class="log-timestamp">Timestamp:</span> {timestamp}<br>
                        <span class="log-tool">Tool:</span> {tool}<br>
                        <span class="log-tool">Step:</span> {step}<br>
                        <span class="log-tool">Input:</span> {entry.get('input', 'N/A')[:100]}
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(preview, language="text")
        else:
            st.info("No execution logs found. Run an investigation first.")
    else:
        st.info("Log directory not found. Run an investigation first.")

with tab4:
    st.markdown("### 📄 Final Report")
    
    log_dir = os.path.expanduser("~/sift-mcp-server/submission/execution_logs")
    
    if os.path.exists(log_dir):
        report_files = sorted([f for f in os.listdir(log_dir) if f.endswith('.md')])
        
        if report_files:
            selected_report = st.selectbox("Select report", report_files)
            report_path = os.path.join(log_dir, selected_report)
            
            with open(report_path, 'r') as f:
                report_content = f.read()
            
            st.markdown(report_content)
        else:
            st.info("No reports found. Run an investigation first.")
    else:
        st.info("Run an investigation to generate a report.")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align:center; opacity:0.5; font-family:'JetBrains Mono', monospace; font-size:0.8rem;">
    SIFT MCP Forensic Agent | Find Evil! Hackathon 2026 | Built by Anjali Jha<br>
    Architectural guardrails, not prompt-based | MIT License
</div>
""", unsafe_allow_html=True)