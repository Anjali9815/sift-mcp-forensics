import subprocess
import json
import os
from mcp.server.fastmcp import FastMCP

server = FastMCP("sift-forensics")


def check_image(image_path: str) -> str | None:
    """Validate that the image file exists. Returns error message or None."""
    if not os.path.exists(image_path):
        return f"Error: File not found at {image_path}. Please provide a valid memory image path."
    return None


@server.tool()
def get_system_info() -> str:
    """Get basic information about this forensic workstation."""
    import platform
    import shutil

    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "disk_free_gb": round(shutil.disk_usage("/").free / (1024**3), 2)
    }

    result = "Forensic Workstation Info:\n"
    for key, value in info.items():
        result += f"  {key}: {value}\n"
    return result


@server.tool()
def get_process_list(image_path: str) -> str:
    """Get list of all processes from a memory image using Volatility 3.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.pslist"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        processes = []
        for entry in data:
            process = {
                "pid": entry.get("PID"),
                "name": entry.get("ImageFileName"),
                "parent_pid": entry.get("PPID"),
                "threads": entry.get("Threads"),
                "create_time": entry.get("CreateTime"),
                "exit_time": entry.get("ExitTime")
            }
            processes.append(process)

        output = f"Found {len(processes)} processes:\n\n"
        for p in processes:
            suspicious = ""
            name = p["name"] or "Unknown"

            if name.lower() in ["stun.exe", "mimikatz.exe", "psexec.exe"]:
                suspicious = " [SUSPICIOUS]"

            output += f"  PID {p['pid']}: {name} (Parent: {p['parent_pid']}){suspicious}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Volatility command timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse Volatility output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


@server.tool()
def get_network_connections(image_path: str) -> str:
    """Get network connections from a memory image using Volatility 3.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.netscan"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        connections = []
        for entry in data:
            conn = {
                "pid": entry.get("PID"),
                "local_addr": entry.get("LocalAddr"),
                "local_port": entry.get("LocalPort"),
                "foreign_addr": entry.get("ForeignAddr"),
                "foreign_port": entry.get("ForeignPort"),
                "state": entry.get("State"),
                "protocol": entry.get("Proto")
            }
            connections.append(conn)

        output = f"Found {len(connections)} network connections:\n\n"
        for c in connections:
            output += f"  PID {c['pid']}: {c['local_addr']}:{c['local_port']} -> {c['foreign_addr']}:{c['foreign_port']} ({c['state']})\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Volatility command timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse Volatility output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 4 — Scan for Malware Injection
@server.tool()
def scan_for_malware(image_path: str) -> str:
    """Scan memory image for injected code and malware using Volatility 3 malfind.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.malfind"],
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        if not data:
            return "No suspicious code injection found."

        output = f"Found {len(data)} suspicious memory regions:\n\n"
        for entry in data:
            output += f"  PID {entry.get('PID')}: {entry.get('Process')}\n"
            output += f"    Address: {entry.get('Start VPN')}\n"
            output += f"    Protection: {entry.get('Protection')}\n"
            output += f"    Tag: {entry.get('Tag')}\n\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Malfind timed out after 180 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 5 — Get Process Tree
@server.tool()
def get_process_tree(image_path: str) -> str:
    """Get process parent-child relationships from memory image.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.pstree"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        output = f"Process Tree ({len(data)} processes):\n\n"
        for entry in data:
            pid = entry.get("PID")
            ppid = entry.get("PPID")
            name = entry.get("ImageFileName", "Unknown")
            output += f"  [{ppid}] -> [{pid}] {name}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Process tree timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 6 — Get Command Lines
@server.tool()
def get_command_lines(image_path: str) -> str:
    """Get command line arguments for all processes from memory image.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.cmdline"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        output = f"Command lines for {len(data)} processes:\n\n"
        for entry in data:
            pid = entry.get("PID")
            name = entry.get("Process", "Unknown")
            args = entry.get("Args", "N/A")
            output += f"  PID {pid} ({name}): {args}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Cmdline timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 7 — List Services
@server.tool()
def get_services(image_path: str) -> str:
    """Get list of Windows services from memory image.

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.svcscan"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        output = f"Found {len(data)} services:\n\n"
        for entry in data:
            name = entry.get("Name", "Unknown")
            display = entry.get("Display", "")
            state = entry.get("State", "Unknown")
            binary = entry.get("Binary", "N/A")

            suspicious = ""
            if binary and any(p in binary.lower() for p in ["\\temp\\", "\\appdata\\", "\\users\\"]):
                suspicious = " [SUSPICIOUS PATH]"

            output += f"  {name}: {state} -> {binary}{suspicious}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Service scan timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 8 — Verify Evidence Integrity
@server.tool()
def verify_evidence(image_path: str) -> str:
    """Calculate hash of evidence file to verify integrity.

    Args:
        image_path: Path to the evidence file
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["sha256sum", image_path],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            return f"Error computing hash: {result.stderr[:200]}"

        file_hash = result.stdout.split()[0]

        size_result = subprocess.run(
            ["stat", "--format=%s", image_path],
            capture_output=True,
            text=True
        )
        file_size = int(size_result.stdout.strip())
        size_gb = round(file_size / (1024**3), 2)

        output = f"Evidence Integrity Report:\n"
        output += f"  File: {image_path}\n"
        output += f"  SHA256: {file_hash}\n"
        output += f"  Size: {size_gb} GB ({file_size} bytes)\n"
        output += f"  Status: Hash computed successfully. Save this hash for chain of custody.\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Hash computation timed out (file may be very large)"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 9 — List Files in Disk Image
@server.tool()
def list_files(image_path: str, search_term: str = "") -> str:
    """List files in a disk image using Sleuth Kit.

    Args:
        image_path: Path to the disk image file (.E01 or raw)
        search_term: Optional search term to filter results
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        cmd = ["fls", "-r", image_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running fls: {result.stderr[:200]}"

        lines = result.stdout.strip().split("\n")

        if search_term:
            lines = [l for l in lines if search_term.lower() in l.lower()]

        if not lines:
            return f"No files found matching '{search_term}'"

        if len(lines) > 100:
            output = f"Found {len(lines)} files (showing first 100):\n\n"
            for line in lines[:100]:
                output += f"  {line}\n"
            output += f"\n  ... and {len(lines) - 100} more files"
        else:
            output = f"Found {len(lines)} files:\n\n"
            for line in lines:
                output += f"  {line}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: File listing timed out after 120 seconds"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 10 — Get Memory Image Info
@server.tool()
def get_image_info(image_path: str) -> str:
    """Get basic information about a memory image (OS version, architecture, etc).

    Args:
        image_path: Path to the memory image file (.img or .raw)
    """
    error = check_image(image_path)
    if error:
        return error

    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.info"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return f"Error running Volatility: {result.stderr[:200]}"

        data = json.loads(result.stdout)

        output = "Memory Image Info:\n\n"
        for entry in data:
            for key, value in entry.items():
                output += f"  {key}: {value}\n"

        return output

    except subprocess.TimeoutExpired:
        return "Error: Image info timed out after 120 seconds"
    except json.JSONDecodeError:
        return f"Error: Could not parse output. Raw: {result.stdout[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


# Tool 11 — Validate Findings (Self-Correction)
@server.tool()
def validate_findings(findings: str, image_path: str) -> str:
    """Cross-check forensic findings for logical consistency.
    
    Takes a set of findings and validates them against the evidence.
    Identifies contradictions, gaps, and areas needing deeper investigation.

    Args:
        findings: Text description of current findings to validate
        image_path: Path to the memory image for re-verification
    """
    error = check_image(image_path)
    if error:
        return error

    checks = []

    # Check 1: Verify any PIDs mentioned in findings actually exist
    try:
        result = subprocess.run(
            ["vol", "-f", image_path, "-r", "json", "windows.pslist"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            valid_pids = {entry.get("PID") for entry in data}

            # Extract PIDs mentioned in findings
            import re
            mentioned_pids = set(re.findall(r'PID\s*(\d+)', findings))
            for pid in mentioned_pids:
                if int(pid) not in valid_pids:
                    checks.append(f"WARNING: PID {pid} mentioned in findings but NOT found in process list")
                else:
                    checks.append(f"VERIFIED: PID {pid} exists in process list")
    except Exception as e:
        checks.append(f"Could not verify PIDs: {str(e)}")

    # Check 2: Look for gaps in analysis
    analysis_areas = {
        "processes": "process" in findings.lower(),
        "network": "network" in findings.lower() or "connection" in findings.lower(),
        "malware": "malware" in findings.lower() or "injection" in findings.lower(),
        "services": "service" in findings.lower(),
        "commands": "command" in findings.lower() or "cmdline" in findings.lower()
    }

    gaps = [area for area, covered in analysis_areas.items() if not covered]
    if gaps:
        checks.append(f"GAPS: The following areas were not covered: {', '.join(gaps)}")
    else:
        checks.append("COVERAGE: All major analysis areas have been addressed")

    output = "Findings Validation Report:\n\n"
    for check in checks:
        output += f"  {check}\n"

    return output


if __name__ == "__main__":
    server.run()
