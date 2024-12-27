from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff, send


class MyCovertChannel(CovertChannelBase):
    def send(self, **kwargs):


        message = "  Raw packet payload 2.0 extra platinium etc"
        payload = Raw(load=message)


        ip_layer = IP(dst="receiver", ttl=1)
        super().send(ip_layer / payload)


        log_file_name = kwargs.get("log_file_name")
        self.log_message(message=message, log_file_name=log_file_name)



        print("Raw IP packet sent successfully!")



    def receive(self, **kwargs):

        # Function to process received packets
        def process_packet(pckt):
            if pckt.haslayer(IP) and pckt[IP].ttl == 1:
                print("Raw IP packet received!")
                if pckt.haslayer(Raw):
                    print(f"Payload: {pckt[Raw].load}")
                    log_file_name = kwargs.get("log_file_name")
                    self.log_message(message="payloadContentHere", log_file_name=log_file_name)


        # Start sniffing for IP packets
        print("Waiting for raw IP packets...")
        sniff(filter="ip", prn=process_packet, timeout=10)

        