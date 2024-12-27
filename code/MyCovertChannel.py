from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


class MyCovertChannel(CovertChannelBase):

    def decode_message(self, input_message, chunk_size=20):
        """
        Encodes the input message by splitting it into chunks.
        """
        return [input_message[i:i + chunk_size] for i in range(0, len(input_message), chunk_size)]


    def encode_message(self, input_message, chunk_size=20):
        message_chunks = []

        for i in range(0, len(input_message), chunk_size):
            chunk = input_message[i:i + chunk_size] 
            message_chunks.append(chunk)
        
        return message_chunks





    def send(self, **kwargs):

        log_file_name = kwargs.get("log_file_name")
        input_message = self.generate_random_binary_message_with_logging( log_file_name=log_file_name, min_length=50, max_length=100)
        

        index = 1
        for chunk in input_message:

            if(chunk == '0'):
                message = '0'
            else:
                message = '1'
            
            payload = Raw(load=message)
            
            ip_layer = IP(dst="receiver", ttl=1)
            super().send(ip_layer / payload)

            print(f"Message Chunk {index} sent: {chunk}\n")
            index += 1




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
        
        
        