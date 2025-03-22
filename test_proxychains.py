#!/usr/bin/env python3

import os
import sys
import time
import socket
import subprocess
import argparse
from pymetasploit3.msfrpc import MsfRpcClient

# Import needed functions
from pengym.utilities import setup_socks_proxy, configure_proxychains

# This is needed because the setup_socks_proxy function likely uses this global variable
from pengym.utilities import msfrpc_client as global_msfrpc_client

def check_port_open(host, port):
    """Check if a port is open on a host"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def run_proxychains_command(command):
    """Run a command through proxychains and return its output"""
    full_command = f"proxychains {command}"
    print(f"\n[+] Running: {full_command}")
    
    try:
        result = subprocess.run(full_command, shell=True, text=True, 
                               capture_output=True, timeout=30)
        
        if result.returncode == 0:
            print("Command completed successfully")
        else:
            print(f"Command failed with return code {result.returncode}")
        
        print(f"STDOUT: {result.stdout[:200]}...")
        if result.stderr:
            print(f"STDERR: {result.stderr[:200]}...")
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("Command timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"Error executing command: {e}")
        return False

def add_host_to_no_proxy(host):
    """Add host to no_proxy environment variable if proxy is in use"""
    # Check for proxy environment variables
    proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
    proxy_in_use = any(var in os.environ for var in proxy_vars)
    
    if proxy_in_use:
        old_no_proxy = os.environ.get('no_proxy', '')
        # Check if host is already in no_proxy
        if host not in old_no_proxy.split(','):
            os.environ['no_proxy'] = f"{host},{old_no_proxy}" if old_no_proxy else host
            os.environ['NO_PROXY'] = os.environ['no_proxy']  # Set both upper and lowercase versions
            print(f"[*] Proxy detected: Added {host} to no_proxy environment variable")
            return True
    return False

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Test SOCKS5 Proxy and Proxychains')
    parser.add_argument('--host', default='127.0.0.1', help='SOCKS proxy host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=9050, help='SOCKS proxy port (default: 9050)')
    parser.add_argument('--password', required=True, help='MSF RPC password')
    parser.add_argument('--msf-host', default='127.0.0.1', help='MSF RPC host (default: 127.0.0.1)')
    parser.add_argument('--msf-port', type=int, default=55553, help='MSF RPC port (default: 55553)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL for MSF RPC connection')
    parser.add_argument('--target', default='1.1.1.1', help='Target to test nmap with (default: 1.1.1.1)')
    args = parser.parse_args()
    
    print("[*] Starting SOCKS5 Proxy and Proxychains Test")
    
    # Step 1: Set up MSF RPC Client
    print(f"[*] Connecting to MSF RPC at {args.msf_host}:{args.msf_port} (SSL: {'enabled' if args.ssl else 'disabled'})")
    
    # Add MSF RPC host to no_proxy if necessary
    add_host_to_no_proxy(args.msf_host)
    
    # Set socket timeout for connection
    socket.setdefaulttimeout(10)
    
    # Test TCP connection first for better error diagnosis
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Testing TCP connection to {args.msf_host}:{args.msf_port}...")
        test_sock.connect((args.msf_host, args.msf_port))
        print("[+] TCP connection successful")
        test_sock.close()
    except Exception as e:
        print(f"[-] TCP connection failed: {e}")
        print("    Check if the MSF RPC service is running.")
        sys.exit(1)
    
    try:
        client = MsfRpcClient(args.password, server=args.msf_host, port=args.msf_port, ssl=args.ssl)
        print("[+] Connected to MSF RPC successfully")
        
        # Important: Set the global msfrpc_client variable that setup_socks_proxy uses
        global global_msfrpc_client
        global_msfrpc_client = client
        
    except Exception as e:
        print(f"[-] Failed to connect to MSF RPC: {e}")
        ssl_option = "--ssl" if args.ssl else ""
        print("    Try starting msfrpcd with:")
        print(f"    msfrpcd -P {args.password} -a {args.msf_host} -p {args.msf_port} {ssl_option}")
        sys.exit(1)
    
    # Reset socket timeout
    socket.setdefaulttimeout(None)

    # Step 2: Set up SOCKS proxy with Metasploit
    print(f"[*] Setting up SOCKS proxy on {args.host}:{args.port}")
    try:
        # Call without client parameter, since it uses the global variable
        proxy_result = setup_socks_proxy(host=args.host, port=args.port)
        if not proxy_result:
            print("[-] Failed to set up SOCKS proxy")
            sys.exit(1)
        print(f"[+] SOCKS proxy setup completed: {proxy_result}")
        
        # Wait for proxy to start
        time.sleep(3)
    except Exception as e:
        print(f"[-] Error setting up SOCKS proxy: {e}")
        sys.exit(1)
    
    # Step 3: Check if SOCKS proxy is listening
    print(f"[*] Checking if SOCKS proxy is listening on {args.host}:{args.port}")
    if check_port_open(args.host, args.port):
        print("[+] SOCKS proxy is listening correctly")
    else:
        print("[-] SOCKS proxy is not listening. Test failed.")
        sys.exit(1)
    
    # Step 4: Configure Proxychains
    print("[*] Configuring Proxychains")
    if configure_proxychains():
        print("[+] Proxychains configured successfully")
    else:
        print("[-] Failed to configure Proxychains")
        sys.exit(1)
    
    # Step 5: Test proxychains with curl to check IP
    print("[*] Testing proxychains with curl")
    success1 = run_proxychains_command("curl -s https://ifconfig.me")
    
    # Step 6: Test proxychains with nmap
    print(f"[*] Testing proxychains with nmap scan against {args.target}")
    success2 = run_proxychains_command(f"nmap -p 80,443 -sT -Pn {args.target}")
    
    # Summary
    print("\n[*] Test Summary:")
    print(f"SOCKS Proxy: {'✅ WORKING' if check_port_open(args.host, args.port) else '❌ NOT WORKING'}")
    print(f"Proxychains with curl: {'✅ WORKING' if success1 else '❌ NOT WORKING'}")
    print(f"Proxychains with nmap: {'✅ WORKING' if success2 else '❌ NOT WORKING'}")
    
    if success1 and success2 and check_port_open(args.host, args.port):
        print("\n[+] All tests PASSED! Your proxychains setup is working correctly.")
    else:
        print("\n[-] Some tests FAILED. Check the configuration and try again.")

if __name__ == "__main__":
    main()