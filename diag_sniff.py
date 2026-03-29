from scapy.all import sniff
import sys

print("[*] Diagnostic: Attempting to capture 1 packet...")
try:
    pkts = sniff(count=1, timeout=5)
    if pkts:
        print(f"[+] Success! Captured 1 packet: {pkts[0].summary()}")
    else:
        print("[-] Timeout: No packets captured in 5 seconds.")
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
