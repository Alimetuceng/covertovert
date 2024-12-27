from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


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

        def process_packet(pckt):
            if pckt.haslayer(IP) and pckt[IP].ttl == 1:
                if pckt.haslayer(Raw):


                    payload = pckt[Raw].load.decode("utf-8", errors="ignore")
                    print(f"Payload: {payload}")
                    
                    
                    # Log the received payload
                    log_file_name = kwargs.get("log_file_name", "receiver.log")  # Default log file if none provided
                    self.log_message(message=payload, log_file_name=log_file_name)


        
        print("Waiting for raw IP packets...")


        sniff(filter="ip", prn=process_packet, timeout=10)

        