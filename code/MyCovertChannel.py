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

            payload = Raw(load=bit)
            
            
            ip_layer = IP(dst="receiver", ttl=1)
            super().send(ip_layer / payload)

            

            print(f"Bit {index} sent: {bit}\n")
            index += 1



    def receive(self, **kwargs):

        log_file_name = kwargs.get("log_file_name", "receiver.log")

        received_bits = []
        decoded_message = []

        def process_packet(pckt):
            nonlocal received_bits, decoded_message

            if pckt.haslayer(IP) and pckt[IP].ttl == 1 and pckt.haslayer(Raw):

                bit = pckt[Raw].load.decode("utf-8", errors="ignore")
                received_bits.append(bit)


                if len(received_bits) == 8:
                    
                    char = self.convert_eight_bits_to_character("".join(received_bits))
                    decoded_message.append(char)

                    received_bits = []

                    print(f"Converted 8 bits to character: {char}\n")
                    

        sniff(filter="ip", prn=process_packet, timeout=20)

        merged_message = "".join(decoded_message)
        self.log_message(message=merged_message, log_file_name=log_file_name)
