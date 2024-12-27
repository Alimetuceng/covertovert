from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, sniff


class MyCovertChannel(CovertChannelBase):
    def send(self, **kwargs):
        # Destination hostname or IP
        dest = "receiver"

        # Define the IP and ICMP layers
        ip_layer = IP(dst=dest, ttl=1)
        icmp_layer = ICMP()

        # Send the packet
        print(f"Sending packet to {dest}...")
        super().send(ip_layer / icmp_layer)
        print("Packet sent successfully!")

    def receive(self, **kwargs):
        # Function to process received packets
        def process_packet(pckt):
            if pckt.haslayer(ICMP) and pckt[IP].ttl == 1:
                print("Packet received!")
                pckt.show()

        # Start sniffing for ICMP packets
        print("Waiting for packets...")
        sniff(filter="icmp", prn=process_packet, timeout=10)
               
