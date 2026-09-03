from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def packet_callback(packet):

    # Make sure packet contains an IP layer
    if IP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst

    # Determine protocol
    if TCP in packet:
        protocol = "TCP"
        details = f"{packet[TCP].sport} -> {packet[TCP].dport}"

    elif UDP in packet:
        protocol = "UDP"
        details = f"{packet[UDP].sport} -> {packet[UDP].dport}"

    elif ICMP in packet:
        protocol = "ICMP"
        details = ""

    else:
        protocol = str(packet[IP].proto)
        details = ""

    print("\n------------------------------")
    print(f"Source      : {source}")
    print(f"Destination : {destination}")
    print(f"Protocol    : {protocol}")
    print(f"Details     : {details}")

    # Display a small amount of payload
    if Raw in packet:
        payload = bytes(packet[Raw].load)

        # Don't print huge/binary payloads
        print(f"Payload     : {payload[:100]!r}")


print("Packet Sniffer Started...")
print("Press CTRL+C to stop.\n")

sniff(prn=packet_callback, store=False)

