from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff


class MyCovertChannel(CovertChannelBase):

    def send(self, **kwargs):
        
        # Generate a random input message for current implementation
        input_message = self.generate_random_message( min_length=50, max_length=100 )


        # Get log file      
        log_file_name = kwargs.get("log_file_name", "sender.log")
        
        # Log input file
        self.log_message( message=input_message, log_file_name=log_file_name )

        # Convert input message to binary
        binary_message = self.convert_string_message_to_binary(input_message)

        print(f"Input Binary Message: {binary_message}\n")

        index = 1

        for bit in binary_message:
            
            ip_layer = IP(dst="receiver", ttl=1)
            header_size = len(ip_layer)
        
            if(bit == "1"):
                payload = Raw(load="1" * (header_size + 10))  # Payload larger than header
            else:
                payload = Raw(load="0" * (header_size - 5))  # Payload smaller than header
            

            pckt = ip_layer / payload


            super().send(pckt)

            

            print(f"Bit {index} sent: {bit}\n")
            index += 1



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

                    print(f"Converted 8 bits to character: {char}\n")
                    

        sniff(
            filter="ip",
            prn=process_packet,
            stop_filter=lambda x: stop_sniffing["stop"]
        )

        merged_message = "".join(decoded_message)
        self.log_message(message=merged_message, log_file_name=log_file_name)
