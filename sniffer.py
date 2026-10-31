import argparse
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
log_file = None


def output(text):
    print(text)
    if log_file:
        log_file.write(text + "\n")


def handle_packet(pkt):
    if IP not in pkt and IPv6 not in pkt:
        return

    ip = pkt[IP] if IP in pkt else pkt[IPv6]
    proto_num = ip.proto if IP in pkt else ip.nh
    proto = PROTOCOLS.get(proto_num, f"Other({proto_num})")
    time = datetime.now().strftime("%H:%M:%S")

    src, dst = ip.src, ip.dst
    if TCP in pkt or UDP in pkt:
        layer = pkt[TCP] if TCP in pkt else pkt[UDP]
        src += f":{layer.sport}"
        dst += f":{layer.dport}"

    output(f"[{time}] {proto:<6} {src} -> {dst} | {len(pkt)} bytes")

    if TCP in pkt:
        output(f"         Flags: {pkt[TCP].flags}")
    if DNS in pkt and pkt[DNS].qd:
        output(f"         DNS query: {pkt[DNS].qd.qname.decode(errors='ignore')}")
    if Raw in pkt:
        data = bytes(pkt[Raw].load)[:60]
        output(f"         Payload: {data}")
    output("-" * 60)


def main():
    global log_file
    parser = argparse.ArgumentParser(description="Basic network sniffer")
    parser.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp', 'udp port 53', 'port 80'")
    parser.add_argument("-i", "--iface", default=None, help="network interface")
    parser.add_argument("-o", "--output", default=None, help="log file to save output")
    args = parser.parse_args()

    if args.output:
        log_file = open(args.output, "a", encoding="utf-8")

    print("Sniffing started... press Ctrl+C to stop.\n")
    try:
        sniff(prn=handle_packet, count=args.count, filter=args.filter, iface=args.iface, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        if log_file:
            log_file.close()
        print("\nSniffing stopped.")


if __name__ == "__main__":
    main()
