import sys
sys.path.insert(0, "src")
from server import (
    get_system_info,
    get_process_list,
    get_network_connections,
    scan_for_malware,
    get_process_tree,
    get_command_lines,
    get_services,
    verify_evidence,
    list_files,
    get_image_info,
    validate_findings
)

print("=== Tool 1: System Info ===")
print(get_system_info())

print("=== Tool 2: Process List ===")
print(get_process_list("/cases/fake.img"))

print("=== Tool 3: Network Connections ===")
print(get_network_connections("/cases/fake.img"))

print("=== Tool 4: Malware Scan ===")
print(scan_for_malware("/cases/fake.img"))

print("=== Tool 5: Process Tree ===")
print(get_process_tree("/cases/fake.img"))

print("=== Tool 6: Command Lines ===")
print(get_command_lines("/cases/fake.img"))

print("=== Tool 7: Services ===")
print(get_services("/cases/fake.img"))

print("=== Tool 8: Verify Evidence ===")
print(verify_evidence("/cases/fake.img"))

print("=== Tool 9: List Files ===")
print(list_files("/cases/fake.img"))

print("=== Tool 10: Image Info ===")
print(get_image_info("/cases/fake.img"))

print("=== Tool 11: Validate Findings ===")
print(validate_findings("Found process with PID 1234", "/cases/fake.img"))