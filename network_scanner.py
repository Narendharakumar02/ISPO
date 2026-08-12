import nmap
import socket
import json

# Step 1: Get local system IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

# Step 2: Build target network
local_ip = get_local_ip()
network_prefix = ".".join(local_ip.split(".")[:3])
TARGET_NETWORK = f"{network_prefix}.0/24"

print(f"\n[*] Local IP detected: {local_ip}")
print(f"[*] Scanning network: {TARGET_NETWORK}\n")

scanner = nmap.PortScanner()

# Step 3: Scan network for live hosts
scanner.scan(
    hosts=TARGET_NETWORK,
    arguments="-sn"
)

live_hosts = []

for host in scanner.all_hosts():
    if scanner[host].state() == "up":
        live_hosts.append(host)

# Step 4: Display discovered IPs
if not live_hosts:
    print("[-] No live hosts found.")
    exit()

print("[+] Live hosts discovered:\n")
for idx, ip in enumerate(live_hosts):
    print(f"{idx + 1}. {ip}")

# Step 5: User selects IP
choice = int(input("\nSelect a host number for detailed scan: ")) - 1
target_ip = live_hosts[choice]

print(f"\n[*] Running detailed scan on {target_ip}...\n")

# Step 6: Detailed scan of selected IP
scanner.scan(
    hosts=target_ip,
    arguments="-sT -sV --open"
)

# Step 7: Convert scan result to JSON
result = {
    "target_ip": target_ip,
    "host_state": scanner[target_ip].state(),
    "protocols": {}
}

for proto in scanner[target_ip].all_protocols():
    ports = scanner[target_ip][proto].keys()
    result["protocols"][proto] = []

    for port in ports:
        port_data = scanner[target_ip][proto][port]
        result["protocols"][proto].append({
            "port": port,
            "state": port_data["state"],
            "service": port_data["name"],
            "product": port_data.get("product", ""),
            "version": port_data.get("version", "")
        })

# Step 8: Save JSON
output_file = "IP_scan.json"

with open(output_file, "w") as f:
    json.dump(result, f, indent=4)

print(f"[+] Scan complete. JSON saved as {output_file}")
