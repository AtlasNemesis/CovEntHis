import argparse
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP
from collections import Counter
from math import log2

def calculate_entropy(data):
    if not data:
        return 0
    total = len(data)
    counts = Counter(data)
    probs = [count / total for count in counts.values()]
    return -sum(p * log2(p) for p in probs if p > 0)

def sliding_entropy(data, window_size=50):
    entropies = []
    for i in range(0, len(data) - window_size + 1):
        window = data[i:i + window_size]
        entropies.append(calculate_entropy(window))
    return entropies

def extract_fields(packets):
    ip_ids, ttls, delays, ttl_lsbs = [], [], [], []
    prev_time = None

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            ip_ids.append(int(ip_layer.id))
            ttls.append(int(ip_layer.ttl))
            ttl_lsbs.append(int(ip_layer.ttl) & 0x1)

            if prev_time is not None:
                delay = float(pkt.time - prev_time)
                delays.append(delay)
            prev_time = pkt.time

    return ip_ids, ttls, delays, ttl_lsbs


def plot_histograms_and_entropy(ip_ids, ttls, delays, ttl_lsbs, basename, save_only):
    fig, axs = plt.subplots(3, 2, figsize=(16, 14))
    fig.suptitle("PCAP Covert Channel Histograms and Entropy", fontsize=18)

    datasets = [
        (ip_ids, "IP ID", axs[0, 0], axs[0, 1]),
        (ttls, "TTL", axs[1, 0], axs[1, 1]),
        (delays, "Inter-Packet Delays", axs[2, 0], axs[2, 1])
    ]

    for data, label, hist_ax, entropy_ax in datasets:
        hist_ax.hist(data, bins=50, color='skyblue', edgecolor='black')
        hist_ax.set_title(f"{label} Histogram")
        hist_ax.set_xlabel(label)
        hist_ax.set_ylabel("Frequency")
        hist_ax.grid(True, linestyle='--', alpha=0.5)

        window_size = min(5, len(data) // 2) if len(data) >= 5 else 1
        entropy_values = sliding_entropy(data, window_size)
        entropy_ax.plot(entropy_values, color='orange')
        entropy_ax.axhline(y=1.0, color='red', linestyle='--', label="Entropy Threshold")
        entropy_ax.set_title(f"{label} Sliding Entropy")
        entropy_ax.set_xlabel("Window Index")
        entropy_ax.set_ylabel("Entropy")
        entropy_ax.grid(True, linestyle='--', alpha=0.5)
        entropy_ax.legend()

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    outname = f"{basename}_histograms_entropy.png"
    plt.savefig(outname)
    print(f"[+] Saved histograms and entropy graph to '{outname}'")

    if not save_only:
        plt.show()
    else:
        plt.close()

def generate_text_report(basename, ip_ids, ttls, delays, ttl_lsbs):
    lsb_counts = Counter(ttl_lsbs)
    lsb_0 = lsb_counts.get(0, 0)
    lsb_1 = lsb_counts.get(1, 0)
    total_lsb = lsb_0 + lsb_1
    lsb_0_pct = (lsb_0 / total_lsb) * 100 if total_lsb else 0
    lsb_1_pct = (lsb_1 / total_lsb) * 100 if total_lsb else 0

    entropy_ttl = calculate_entropy(ttls)
    entropy_id = calculate_entropy(ip_ids)
    entropy_delay = calculate_entropy(delays)
    entropy_lsb = calculate_entropy(ttl_lsbs)

    report = f"""=== PCAP Covert Channel Analysis ===
File: {basename}.pcap
Total IP Packets: {len(ip_ids)}

[TTL LSB Analysis]
 - LSB(0): {lsb_0_pct:.1f}%
 - LSB(1): {lsb_1_pct:.1f}%
 - Observation: {"Skewed distribution suggests possible covert signaling." if abs(lsb_0_pct - 50) > 20 else "LSB distribution appears normal."}

[Entropy Scores]
 - TTL Entropy: {entropy_ttl:.2f}
 - IP ID Entropy: {entropy_id:.2f}
 - Inter-Packet Delay Entropy: {entropy_delay:.2f}
 - TTL LSB Entropy: {entropy_lsb:.2f}
 - Observation: {"Low delay entropy or TTL LSB entropy may indicate timing or bit-based covert channel." if entropy_delay < 3 or entropy_lsb < 0.9 else "No obvious entropy anomalies detected."}
"""

    report_file = f"{basename}_analysis.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"[+] Saved analysis report to '{report_file}'")

def main():
    parser = argparse.ArgumentParser(description="PCAP Covert Channel Analyzer with Histogram and Entropy")
    parser.add_argument("pcap_file", help="Path to the .pcap file")
    parser.add_argument("--save", action="store_true", help="Save output files and suppress plots")
    args = parser.parse_args()

    pcap_file = args.pcap_file
    basename = os.path.splitext(os.path.basename(pcap_file))[0]

    try:
        packets = rdpcap(pcap_file)
        ip_ids, ttls, delays, ttl_lsbs = extract_fields(packets)

        print(f"[+] Analyzing {len(ip_ids)} IP packets from '{pcap_file}'...")
        plot_histograms_and_entropy(ip_ids, ttls, delays, ttl_lsbs, basename, args.save)
        generate_text_report(basename, ip_ids, ttls, delays, ttl_lsbs)

    except Exception as e:
        print(f"[!] Error processing PCAP: {e}")

if __name__ == "__main__":
    main()
