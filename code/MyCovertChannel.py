from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff, send


class MyCovertChannel(CovertChannelBase):
    def send(self, **kwargs):

        ip_layer = IP(dst="receiver", ttl=1)

        # Add an optional payload (Raw layer)
        message = "  Raw packet payload  "
        payload = Raw(load=message)

        super().send(ip_layer / payload)

        print("Raw IP packet sent successfully!")

    def receive(self, **kwargs):

        # Function to process received packets
        def process_packet(pckt):
            if pckt.haslayer(IP) and pckt[IP].ttl == 1:
                print("Raw IP packet received!")
                if pckt.haslayer(Raw):
                    print(f"Payload: {pckt[Raw].load}")

        # Start sniffing for IP packets
        print("Waiting for raw IP packets...")
        sniff(filter="ip", prn=process_packet, timeout=10)