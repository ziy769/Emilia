# create by mayumi v.1
"""
NOte add lib re
"""
import socket
import ssl
import json
import concurrent.futures
import re

IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
PROXY_FILE = "Data/RawProxyISP.txt"
OUTPUT_FILE = "Data/alive.txt"

active_proxies = []  # List untuk menyimpan proxy aktif

def check(host, path, proxy):
    """Melakukan koneksi SSL ke host tertentu dan mengambil respons JSON."""
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n"
        "Connection: close\r\n\r\n"
    )

    ip = proxy.get("ip", host)
    port = int(proxy.get("port", 443))

    conn = None
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((ip, port), timeout=15)
        conn = ctx.wrap_socket(conn, server_hostname=host)

        conn.sendall(payload.encode())

        resp = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            resp += data

        resp = resp.decode("utf-8", errors="ignore")
        headers, body = resp.split("\r\n\r\n", 1)

        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        print(f"Error parsing JSON dari {ip}:{port}")
    except (socket.error, ssl.SSLError) as e:
        print(f"Error koneksi: {e}")
    finally:
        if conn:
            conn.close()

    return {}

def clean_org_name(org_name): #Menghapus karakter yang tidak diinginkan dari nama organisasi.
    return re.sub(r'[^a-zA-Z0-9\s]', '', org_name) if org_name else org_name

def process_proxy(proxy_line):
    proxy_line = proxy_line.strip()
    if not proxy_line:
        return

    try:
        ip, port, country, org = proxy_line.split(",")
        proxy_data = {"ip": ip, "port": port}

        ori, pxy = [
            check(IP_RESOLVER, PATH_RESOLVER, {}),
            check(IP_RESOLVER, PATH_RESOLVER, proxy_data)
        ]

        if ori and pxy and ori.get("clientIp") != pxy.get("clientIp"):
            
            org_name = clean_org_name(pxy.get("asOrganization"))
            proxy_country = pxy.get("country")

            proxy_entry = f"{ip},{port},{country},{org_name}"
            print(f"CF PROXY LIVE!: {proxy_entry}")
            active_proxies.append(proxy_entry)

        else:
            print(f"CF PROXY DEAD!: {ip}:{port}")

    except ValueError:
        print(f"Format baris proxy tidak valid: {proxy_line}. Pastikan formatnya ip,port,country,org")
    except Exception as e:
        print(f"Error saat memproses proxy {proxy_line}: {e}")

# Kosongkan file sebelum memulai scan
open(OUTPUT_FILE, "w").close()
print(f"File {OUTPUT_FILE} telah dikosongkan sebelum proses scan dimulai.")

# Membaca daftar proxy dari file
try:
    with open(PROXY_FILE, "r") as f:
        proxies = f.readlines()
except FileNotFoundError:
    print(f"File tidak ditemukan: {PROXY_FILE}")
    exit()

max_workers = 40

with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_proxy, proxy_line) for proxy_line in proxies]
    concurrent.futures.wait(futures)

# Setelah semua proxy diproses, simpan ke file
if active_proxies:
    with open(OUTPUT_FILE, "w") as f_live:
        f_live.write("\n".join(active_proxies) + "\n")
    print(f"Semua proxy aktif disimpan ke {OUTPUT_FILE}")

print("Pengecekan proxy selesai.")
