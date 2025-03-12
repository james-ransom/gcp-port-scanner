import socket
import sys
import argparse
import subprocess
import json
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_private_ip(ip):
    """Check if the IP is in a private 10.x.x.x range."""
    return re.match(r"^10\.", ip) is not None

def get_gcp_vm_ips():
    """Retrieve external IP addresses of GCP VMs."""
    try:
        result = subprocess.run(
            ["gcloud", "compute", "instances", "list", "--format=json"],
            capture_output=True, text=True, check=True,
        )
        instances = json.loads(result.stdout)
        return {
            instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"]: f"VM ({instance['name']})"
            for instance in instances if "networkInterfaces" in instance
            and instance["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
            and not is_private_ip(instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"])
        }
    except subprocess.CalledProcessError as e:
        print(f"[!] Error retrieving GCP VMs: {e}")
        return {}

def get_gke_loadbalancer_ips():
    """Retrieve external IP addresses of Kubernetes LoadBalancer services."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "svc", "--all-namespaces", "-o", "json"],
            capture_output=True, text=True, check=True,
        )
        services = json.loads(result.stdout)
        return {
            ip_info["ip"]: f"GKE LoadBalancer ({svc['metadata']['namespace']}/{svc['metadata']['name']})"
            for svc in services.get("items", []) if svc.get("spec", {}).get("type") == "LoadBalancer"
            for ip_info in svc.get("status", {}).get("loadBalancer", {}).get("ingress", [])
            if "ip" in ip_info and not is_private_ip(ip_info["ip"])
        }
    except subprocess.CalledProcessError as e:
        print(f"[!] Error retrieving GKE LoadBalancer services: {e}")
        return {}

def get_gke_node_ips():
    """Retrieve external IP addresses of Kubernetes nodes."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "nodes", "-o", "json"],
            capture_output=True, text=True, check=True,
        )
        nodes = json.loads(result.stdout)
        return {
            address["address"]: f"GKE Node ({node['metadata']['name']})"
            for node in nodes.get("items", []) 
            for address in node.get("status", {}).get("addresses", []) 
            if address.get("type") == "ExternalIP" and not is_private_ip(address["address"])
        }
    except subprocess.CalledProcessError as e:
        print(f"[!] Error retrieving GKE Node external IPs: {e}")
        return {}

def get_gcp_reserved_ips():
    """Retrieve external reserved IP addresses in GCP."""
    try:
        result = subprocess.run(
            ["gcloud", "compute", "addresses", "list", "--format=json"],
            capture_output=True, text=True, check=True,
        )
        addresses = json.loads(result.stdout)
        return {
            address["address"]: f"Reserved GCP IP ({address.get('name', 'reserved-address')})"
            for address in addresses if address.get("address") and not is_private_ip(address["address"])
            and address.get("status") == "IN_USE"
        }
    except subprocess.CalledProcessError as e:
        print(f"[!] Error retrieving GCP reserved external IPs: {e}")
        return {}

def scan_port(target, port, label):
    """Check if a port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            if sock.connect_ex((target, port)) == 0:
                return [target, port, "OPEN", label]
    except Exception:
        pass
    return None

def scan_ports(targets, ports, workers=20):
    """Scan multiple ports in parallel."""
    print(f"Scanning {len(targets)} targets with {workers} threads...\n")
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_target_port = {
            executor.submit(scan_port, ip, port, label): (ip, port, label)
            for ip, label in targets.items() for port in ports
        }

        for future in as_completed(future_to_target_port):
            result = future.result()
            if result:
                print(f"[OPEN] {result[0]}:{result[1]} -> {result[3]}")
                open_ports.append(result)

    if open_ports:
        write_results_to_csv(open_ports)
    else:
        print("No open ports found.")

def write_results_to_csv(results):
    """Write scan results to CSV."""
    with open("scan_results.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Port", "Status", "Label"])
        writer.writerows(results)
    print("\n✅ Scan results saved to scan_results.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel Port Scanner for GCP VMs, GKE Nodes, LoadBalancers, and Reserved IPs")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports", default=None)

    args = parser.parse_args()
    
    gcp_vm_ips = get_gcp_vm_ips()
    gke_lb_ips = get_gke_loadbalancer_ips()
    gke_node_ips = get_gke_node_ips()
    gcp_reserved_ips = get_gcp_reserved_ips()

    targets = {**gcp_vm_ips, **gke_lb_ips, **gke_node_ips, **gcp_reserved_ips}

    if not targets:
        print("[!] No external IPs found.")
        sys.exit(1)
    
    ports = [int(port) for port in args.ports.split(",")] if args.ports else [
        80, 443, 22, 3389, 8080, 8443, 3306, 11211, 6379, 9901, 9902, 21, 10250, 10259, 10257, 6443, 
        5432, 25, 23, 53, 111, 135, 139, 143, 5900
    ]

    scan_ports(targets, ports)
