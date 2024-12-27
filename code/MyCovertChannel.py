from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


class MyCovertChannel(CovertChannelBase):


    def send(self, **kwargs):

        
        for i in range(5):

            message = self.generate_random_message( min_length=50, max_length=100)
            payload = Raw(load=message)


            ip_layer = IP(dst="receiver", ttl=1)
            super().send(ip_layer / payload)


            log_file_name = kwargs.get("log_file_name")
            self.log_message(message=message, log_file_name=log_file_name)


            print(f"Message {i + 1} sent: {message}\n")



        print("Raw packets are sent successfully!\n")



    def receive(self, **kwargs):

        received_messages = []


        def process_packet(pckt):

            if pckt.haslayer(IP) and pckt[IP].ttl == 1 and pckt.haslayer(Raw):
                    

                    payload = pckt[Raw].load.decode("utf-8", errors="ignore")
                    

                    received_messages.append(payload)
                    print(f"Payload: {payload} is added to received_messages.\n")
                    

                    log_file_name = kwargs.get("log_file_name")
                    self.log_message(message=payload, log_file_name=log_file_name)

        
        print("Waiting for raw IP packets...\n")


        sniff(filter="ip", prn=process_packet, timeout=30)
        
        
        
        