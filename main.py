import argparse as ap
import socket
from concurrent.futures import ThreadPoolExecutor
import time as t
import json

from rich.console import Console
from rich.table import Table
console = Console()


Vuln_db= {"ports":{},"keywords":{}}

def get_vulnDb(port,bann):
    bann_lower= bann.lower()
    for keyword, hint in Vuln_db.get("keywords",{}).items():
        if keyword in bann_lower:
            return hint
    return Vuln_db.get("ports",{}).get(str(port), "Safe/ No common automated hints.")

def probe_ports(target_ip,port):
    scanner = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    scanner.settimeout(1.0)
    result =scanner.connect_ex((target_ip,port))

    if result == 0:
        bann= banner_grab(scanner)
        scanner.close()
        return (port,bann)
    return None

def parse_ports(ports_str):
    try:
        if '-' in ports_str:
            start,end= map(int, ports_str.split('-'))
            return range(start,end +1)
        else :
            return [int(ports_str)]
    except ValueError:
        raise ap.ArgumentTypeError("INVALID PORT NUMBER!")

def banner_grab(connected_socks):
    try:
        connected_socks.settimeout(1.2)
        bann=connected_socks.recv(1024)
        if bann:
            return bann.decode('utf-8',errors='ignore').strip()
    except socket.timeout:
        try:
            astronaut =b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            connected_socks.sendall(astronaut)
            bann=connected_socks.recv(1024)
            if bann:
                return bann.decode('utf-8', errors='ignore').strip()
        except socket.error:
            pass
    return "Unknown service (no banner received)"

def main():
    global Vuln_db
    parser =ap.ArgumentParser(description= "Network scanner by Pavan")
    parser.add_argument("target", help= "Enter target ip address (ex: 192.168.0.xxx)")
    parser.add_argument("-p","--ports", type=parse_ports, default="1-1024", help="Enter ports to scan")
    parser.add_argument("-t","--threads", type=int, default= 50, help="Number of concurrent worker threads(default=50)")
    parser.add_argument("-db","--database", type=str, default="vulnerabilities.json", help="Database to use for vulnerability hints")
    args = parser.parse_args()
    try:
        with open(args.database, "r") as f:
            Vuln_db = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red][!][/bold red] Warning: {args.database} not found. Running without hints.")

    print("Scanning target...")
    t.sleep(2)
    print(f"Total ports to check:{len(args.ports)}")
    t.sleep(2)
    print(f'Using {args.threads} threads....\n')

    open_ports=[]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results=executor.map(lambda p: probe_ports(args.target,p),args.ports)
        for result in results:
            if result is not None:
                port,bann=result
                print(f"[+] Port {port} is open | Banner: {bann}")
                open_ports.append((port,bann))


    if open_ports:
        table= Table(title=f"\nScan Results for {args.target}", show_header=True, header_style="bold red")
        table.add_column("Port", style='cyan', justify='right')
        table.add_column("Status", style='green')
        table.add_column("Security Banner", style='white')
        table.add_column("Security Warning/ Hint", style='yellow')

        for port, banner in open_ports:
            hint = get_vulnDb(port, banner)
            table.add_row(str(port), "OPEN", banner, hint)

        console.print(table)
    else:
        console.print(f"\n[bold red][!][/bold red] Scan complete. No open ports discovered on {args.target}.")



if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScanning Stopped due to CTRL+C")