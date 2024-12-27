from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


class MyCovertChannel(CovertChannelBase):


    def send(self, **kwargs):


        sent_messages = []
        
        for i in range(5):

            message = self.generate_random_message( min_length=50, max_length=100)
            sent_messages.append(message)
            
            payload = Raw(load=message)
            

            ip_layer = IP(dst="receiver", ttl=1)
            super().send(ip_layer / payload)


            print(f"Message {i + 1} sent: {message}\n")

        
        log_file_name = kwargs.get("log_file_name")
        merged_messages = "".join(sent_messages)
        self.log_message(message=merged_messages, log_file_name=log_file_name)
        
        
        print("Raw packets are sent successfully!\n")



    def receive(self, **kwargs):

        received_messages = []


        def process_packet(pckt):

            if pckt.haslayer(IP) and pckt[IP].ttl == 1 and pckt.haslayer(Raw):
                    

                    payload_message = pckt[Raw].load.decode("utf-8", errors="ignore")
                    

                    received_messages.append(payload_message)
                    print(f"Payload: {payload_message} is added to received_messages.\n")

        
        print("Waiting for raw IP packets...\n")


        sniff(filter="ip", prn=process_packet, timeout=10)


        log_file_name = kwargs.get("log_file_name")


        merged_messages = "".join(received_messages)
        self.log_message(message=merged_messages, log_file_name=log_file_name)
        
        
        