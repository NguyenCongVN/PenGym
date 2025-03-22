#!/usr/bin/env python3
import socket
import ssl
import struct

def msfrpc_connect(host, port, username, password, ssl_enabled=False):
    print(f"Connecting to {host}:{port} (SSL: {ssl_enabled})")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if ssl_enabled:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock)
    
    try:
        sock.connect((host, port))
        print("TCP connection established")
        
        # Construct login request
        auth_string = f"auth.login\x00{username}\x00{password}"
        header = struct.pack(">I", len(auth_string))
        sock.send(header + auth_string.encode())
        
        # Read response
        header = sock.recv(4)
        if not header or len(header) != 4:
            print("Failed to receive response header")
            return
            
        length = struct.unpack(">I", header)[0]
        response = sock.recv(length)
        print(f"Received response: {response}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

# Try both non-SSL and SSL
msfrpc_connect("44.1.0.10", 55553, "msf", "cyuser", False)
print("\nTrying with SSL enabled:")
msfrpc_connect("44.1.0.10", 55553, "msf", "cyuser", True)