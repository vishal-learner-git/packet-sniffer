"""
demo_data.py
------------
Provides realistic sample packet and alert data for Demo Mode.
Features 100+ packets and 5 distinct network threat scenarios.
"""

import pandas as pd
import random
from datetime import datetime, timedelta

def get_demo_packets():
    """Returns a large DataFrame of sample captured packets with diverse scenarios."""
    packets = []
    base_time = datetime.now() - timedelta(minutes=5)
    
    # 1. Normal Traffic Base (60 packets)
    for i in range(60):
        t = (base_time + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S")
        proto = random.choices(["TCP", "UDP", "ICMP", "ARP"], weights=[0.7, 0.2, 0.05, 0.05])[0]
        src_ip = random.choice(["192.168.1.7", "192.168.1.15", "192.168.1.22"])
        dst_ip = random.choice(["142.250.180.14", "1.1.1.1", "8.8.8.8", "192.168.1.1"])
        
        pkt = {
            "Timestamp": t,
            "Protocol": proto,
            "Size": random.randint(40, 1500),
            "Src_IP": src_ip,
            "Dst_IP": dst_ip,
            "Src_Port": random.randint(49152, 65535) if proto in ["TCP", "UDP"] else None,
            "Dst_Port": random.choice([80, 443, 53]) if proto in ["TCP", "UDP"] else None,
            "TCP_Flags": "A" if proto == "TCP" else None,
            "ICMP_Type": 8 if proto == "ICMP" else None,
            "ICMP_Code": 0 if proto == "ICMP" else None,
            "MAC_Src": f"a4:c3:f0:11:22:{random.randint(10,99)}",
            "MAC_Dst": "c8:d7:19:aa:bb:cc"
        }
        packets.append(pkt)

    # 2. Port Scan Scenario (20 packets)
    # Scenario: 10.0.0.55 scanning ports 20-100 on 192.168.1.7
    scan_time = base_time + timedelta(minutes=1)
    for port in range(20, 100, 4):
        packets.append({
            "Timestamp": (scan_time + timedelta(milliseconds=port*10)).strftime("%Y-%m-%d %H:%M:%S"),
            "Protocol": "TCP",
            "Size": 44,
            "Src_IP": "10.0.0.55",
            "Dst_IP": "192.168.1.7",
            "Src_Port": 61234,
            "Dst_Port": port,
            "TCP_Flags": "S",
            "ICMP_Type": None,
            "ICMP_Code": None,
            "MAC_Src": "b8:27:eb:12:34:56",
            "MAC_Dst": "a4:c3:f0:11:22:33"
        })

    # 3. SYN Flood Scenario (20 packets)
    # Scenario: 10.0.0.99 flooding port 80
    flood_time = base_time + timedelta(minutes=2)
    for i in range(20):
        packets.append({
            "Timestamp": (flood_time + timedelta(milliseconds=i*50)).strftime("%Y-%m-%d %H:%M:%S"),
            "Protocol": "TCP",
            "Size": 44,
            "Src_IP": "10.0.0.99",
            "Dst_IP": "192.168.1.1",
            "Src_Port": random.randint(1024, 65535),
            "Dst_Port": 80,
            "TCP_Flags": "S",
            "ICMP_Type": None,
            "ICMP_Code": None,
            "MAC_Src": "de:ad:be:ef:12:34",
            "MAC_Dst": "c8:d7:19:aa:bb:cc"
        })

    # 4. Sensitive Port Access (5 packets)
    sens_time = base_time + timedelta(minutes=3)
    for i, port in enumerate([22, 23, 3389, 445, 21]):
        packets.append({
            "Timestamp": (sens_time + timedelta(seconds=i*5)).strftime("%Y-%m-%d %H:%M:%S"),
            "Protocol": "TCP",
            "Size": 60,
            "Src_IP": "10.0.0.105",
            "Dst_IP": "192.168.1.1",
            "Src_Port": 55123,
            "Dst_Port": port,
            "TCP_Flags": "S",
            "ICMP_Type": None,
            "ICMP_Code": None,
            "MAC_Src": "f2:31:09:88:77:66",
            "MAC_Dst": "c8:d7:19:aa:bb:cc"
        })

    # 5. ICMP Flood (15 packets)
    icmp_time = base_time + timedelta(minutes=4)
    for i in range(15):
        packets.append({
            "Timestamp": (icmp_time + timedelta(milliseconds=i*100)).strftime("%Y-%m-%d %H:%M:%S"),
            "Protocol": "ICMP",
            "Size": 74,
            "Src_IP": "10.0.0.210",
            "Dst_IP": "192.168.1.1",
            "Src_Port": None,
            "Dst_Port": None,
            "TCP_Flags": None,
            "ICMP_Type": 8,
            "ICMP_Code": 0,
            "MAC_Src": "aa:bb:cc:dd:ee:ff",
            "MAC_Dst": "c8:d7:19:aa:bb:cc"
        })

    return pd.DataFrame(packets).sort_values("Timestamp")


def get_demo_alerts():
    """Returns a list of realistic alert strings for the demo scenarios."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        f"[{now_str}] ALERT: PORT_SCAN from 10.0.0.55 | Reason: Reconnaissance detected: Scanned 20 unique ports in 2.0s",
        f"[{now_str}] ALERT: SYN_FLOOD from 10.0.0.99 | Reason: DoS Warning: High SYN rate (20 pkts/s) detected from single source",
        f"[{now_str}] ALERT: SENSITIVE_PORT_ACCESS from 10.0.0.105 | Reason: Unauthorized access attempt to SSH (Port 22)",
        f"[{now_str}] ALERT: SENSITIVE_PORT_ACCESS from 10.0.0.105 | Reason: Unauthorized access attempt to RDP (Port 3389)",
        f"[{now_str}] ALERT: ICMP_FLOOD from 10.0.0.210 | Reason: DoS Warning: High ICMP Echo Request rate detected",
        f"[{now_str}] ALERT: HIGH_TRAFFIC_SOURCE from 10.0.0.15 | Reason: Anomaly: Source transmitting over 50MB in 60s"
    ]

def get_demo_traffic_over_time():
    """Returns a list of data points for a traffic chart."""
    data = []
    now = datetime.now()
    for i in range(24):
        t = (now - timedelta(hours=23-i)).strftime("%H:00")
        data.append({
            "time": t,
            "packets": random.randint(100, 1000) if 8 <= i <= 18 else random.randint(10, 100)
        })
    return data
