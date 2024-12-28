from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


class MyCovertChannel(CovertChannelBase):

    def send(self, **kwargs):
        

        input_message = self.generate_random_message( min_length=50, max_length=100 )

 
        log_file_name = kwargs.get("log_file_name", "sender.log")
        

        self.log_message( message=input_message, log_file_name=log_file_name )


        binary_message = self.convert_string_message_to_binary(input_message)


        for bit in binary_message:
            
            ip_layer = IP(dst="receiver", ttl=1)
            header_size = len(ip_layer)
        
            if(bit == "1"):
                payload = Raw(load="1" * (header_size + 10))
            else:
                payload = Raw(load="0" * (header_size - 5)) 
            

            pckt = ip_layer / payload


            super().send(pckt)




    def receive(self, **kwargs):

        log_file_name = kwargs.get("log_file_name", "receiver.log")

        received_bits = []
        decoded_message = []

        stop_sniffing = {"stop": False}

        def process_packet(pckt):
            nonlocal received_bits, decoded_message
            
            
            
            if pckt.haslayer(IP) and pckt[IP].ttl == 1 and pckt.haslayer(Raw):
                
                
                payload_size = len(pckt[Raw].load)
                header_size = len(pckt[IP]) - payload_size

                if payload_size > header_size:
                    bit = "1" 
                else:
                    bit = "0"  # Threshold for long/short payload
                
                
                received_bits.append(bit)


                if len(received_bits) == 8:
                    
                    char = self.convert_eight_bits_to_character("".join(received_bits))
                    decoded_message.append(char)

                    if(char == '.'):
                        stop_sniffing["stop"] = True
                        return

                    received_bits = []
                    

        sniff(
            filter="ip",
            prn=process_packet,
            stop_filter=lambda x: stop_sniffing["stop"]
        )

        merged_message = "".join(decoded_message)
        self.log_message(message=merged_message, log_file_name=log_file_name)
