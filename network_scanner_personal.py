import argparse
import nmap
import sys
from colorama import Fore, Style

def argument_parser():
    parser = argparse.ArgumentParser(
        description="TCP port scanner. Accept a HostName/IP Address and list of ports to scan. "
                   "Attempts to identify the service running on a port."
    )
    parser.add_argument("-H", "--host", nargs="?", default="127.0.0.1",
                      help="Host IP Address (default: %(default)s)")
    parser.add_argument("-p", "--port", nargs="?", default="80",
                      help="Comma-separated port list, such as '25,80,8000' (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Show all ports including filtered/closed ones")
    return vars(parser.parse_args())

def nmap_scan(host_id, port_num, verbose=False):
    try:
        scanner = nmap.PortScanner()
        port_num_cleaned = port_num.replace(" ", "")
        if not port_num_cleaned:
            return [f"\n{Fore.RED}[!] No valid ports specified{Style.RESET_ALL}"]
            
        print(f"\n{Fore.GREEN}[*] Scanning {host_id} on port(s): {port_num_cleaned}{Style.RESET_ALL}")
        
        # Host discovery with timeout
        scanner.scan(host_id, arguments="-sn --host-timeout 5s")
        if host_id not in scanner.all_hosts():
            return [f"\n{Fore.RED}[!] Host {host_id} | Host is down or blocking ICMP{Style.RESET_ALL}"]
        
        print(f"\n{Fore.GREEN}[*] Starting port scan...{Style.RESET_ALL}")
        scanner.scan(host_id, arguments=f"-sT -p {port_num_cleaned} --host-timeout 10s")
        
        result = []
        for port_entry in port_num_cleaned.split(","):
            port_entry = port_entry.strip()
            
            if '-' in port_entry:  # Handle port ranges
                try:
                    start, end = map(int, port_entry.split('-'))
                    for port in range(start, end + 1):
                        process_port(scanner, host_id, port, result, verbose)
                except ValueError:
                    result.append(f"\n{Fore.RED}[-] Invalid port range: {port_entry}{Style.RESET_ALL}")
                    continue
                    
            elif port_entry.isdigit():  # Handle single port
                process_port(scanner, host_id, int(port_entry), result, verbose)
                
            else:  # Invalid port format
                result.append(f"\n{Fore.RED}[-] Invalid port format: {port_entry}{Style.RESET_ALL}")
                
        return result
        
    except nmap.PortScannerError as e:
        return [f"\n{Fore.RED}[!] NMAP Error: {str(e)}{Style.RESET_ALL}"]
    except Exception as e:
        return [f"\n{Fore.RED}[!] Unexpected Error: {str(e)}{Style.RESET_ALL}"]

def process_port(scanner, host_id, port, result, verbose=False):
    try:
        port_info = scanner[host_id]["tcp"][port]
        state = port_info["state"]
        service = port_info.get("name", "unknown")
        
        if state == "open":
            result.append(f"\n{Fore.WHITE}[+] Host: {host_id} | Port: {port}/tcp | State: {state} | Service: {service}{Style.RESET_ALL}")
        elif verbose:  # Only show non-open ports if verbose mode is enabled
            if state == "filtered":
                result.append(f"\n{Fore.CYAN}[-] Host: {host_id} | Port: {port}/tcp | State: {state}{Style.RESET_ALL}")
            else:  # closed or other states
                result.append(f"\n{Fore.YELLOW}[-] Host: {host_id} | Port: {port}/tcp | State: {state}{Style.RESET_ALL}")
            
    except KeyError:
        if verbose:
            result.append(f"\n{Fore.CYAN}[-] Host: {host_id} | Port: {port}/tcp | No response (filtered or closed){Style.RESET_ALL}")

def main():
    try:
        args = argument_parser()
        result = nmap_scan(args["host"], args["port"], args["verbose"])
        
        if not result:
            print(f"\n{Fore.YELLOW}[!] No scan results returned{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.MAGENTA}[*] Scan Results:{Style.RESET_ALL}")
        for r in result:
            print(r)
            
        # Show summary
        open_ports = sum(1 for r in result if "[+]" in r)
        hidden_ports = sum(1 for r in result if "[-]" in r) if args["verbose"] else 0
        if not args["verbose"] and hidden_ports > 0:
            print(f"\n{Fore.CYAN}[*] {hidden_ports} filtered/closed ports hidden (use -v to show){Style.RESET_ALL}")
            
        print(f"\n{Fore.GREEN}[*] Found {open_ports} open ports{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[*] Scan Completed.{Style.RESET_ALL}")
        
    except AttributeError:
        print(f"\n{Fore.CYAN}[-] Failed argument input | Provide valid arguments{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Keyboard interrupt by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()