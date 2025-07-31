#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from rich.table import Table
from rich.console import Console
import socket
import signal
import sys

console = Console()

def signal_handler(sig, frame):
    console.print("\n[bold red]Cancelar Escaneo de Puertos Activos En Red (Ctrl+C).[/bold red]")
    sys.exit(0)

def scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = None

        if hostname:
            host_display = hostname
        else:
            port = scan_ports(ip)
            host_display = ','.join(port) if port else "No Hay Puertos"

        try:
            os_guess, ttl = guess_os(ip)
        except:
            os_guess, ttl = "Desconocido", None

        devices.append({
            "ip": ip,
            "mac": mac,
            "host": host_display,
            "os": os_guess,
            "ttl": str(ttl) if ttl else "?"
        })

    return devices

def display(devices):
    table = Table(title="Encontrados")
    table.add_column("IP", justify="left")
    table.add_column("MAC", justify="left")
    table.add_column("Host / Puertos", justify="left")
    table.add_column("Sistema operativo", justify="left")
    table.add_column("TTL", justify="center")

    for d in devices:
        table.add_row(d["ip"], d["mac"], d["host"], d["os"], d["ttl"])

    console.print(table)

def scan_ports(ip, ports=[20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 3306, 3389, 5432, 5900, 5984, 6379, 6667, 8000, 8080, 8443, 9000, 9200]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
            sock.close()
        except:
            continue
    return open_ports


def guess_os(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is None:
            return "Desconocido", None

        ttl = resp.ttl
        if ttl >= 128:
            return "Windows", ttl
        elif ttl == 64:
            return "Linux/Unix/MacOS", ttl
        else:
            return "Desconocido", ttl
    except Exception as e:
        return "Desconocido", None

def list_network_interfaces():
    import subprocess, re
    interfaces = []
    output = subprocess.check_output("ip -o -f inet addr show", shell=True).decode()
    for line in output.splitlines():
        if " lo " in line:
            continue
        match = re.match(r'\d+: (\w+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
        if match:
            iface, ip, mask = match.groups()
            interfaces.append((iface, f"{ip}/{mask}"))
    return interfaces

def get_subnet_from_interface(interface_name):
    import subprocess, re
    try:
        output = subprocess.check_output(f"ip -o -f inet addr show {interface_name}", shell=True).decode()
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', output)
        if match:
            ip = match.group(1)
            mask = match.group(2)
            return f"{ip}/{mask}"
    except:
        return None

if __name__ == "__main__":
    interfaces = list_network_interfaces()
    if not interfaces:
        print("No se encontraron interfaces de red válidas.")
        exit(1)

    console.print("[bold green]Interfaces de red:[/bold green]")
    for i, (iface, ip) in enumerate(interfaces):
        console.print(f"[{i}] {iface} → {ip}")

    try:
        choice = int(input("Selecciona la interfaz: "))
        selected_iface = interfaces[choice][0]
        subnet = get_subnet_from_interface(selected_iface)
        if not subnet:
            print("No se pudo obtener la subred de esa interfaz.")
            exit(1)
    except (ValueError, IndexError):
        print("Selección no valida.")
        exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    console.print(f"\n[cyan]Escaneando red en la interfaz, Espere porfavor [bold]{selected_iface}[/bold]: {subnet}[/cyan]\n")
    devices = scan(subnet)
    display(devices)
