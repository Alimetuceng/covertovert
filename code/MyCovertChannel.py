


from CovertChannelBase import CovertChannelBase
from scapy.all import *
from datetime import datetime
import time

class MyCovertChannel(CovertChannelBase):
    
    def ntp_timestamp(self):
        # Calculate the NTP timestamp as a float (seconds since 1900-01-01)
        ntp_epoch = datetime(1900, 1, 1)
        current_time = datetime.utcnow()
        delta = current_time - ntp_epoch
        seconds = int(delta.total_seconds())  # Integer part (seconds)
        fraction = (delta.total_seconds() - seconds) * (2**32)  # Fractional part as a float
        return seconds + fraction / (2**32)  # Return as a float
    
    
    
    def send(self, **kwargs):
        

        input_message = kwargs.get("message")
        log_file_name = kwargs.get("log_file_name", "sender.log")
        inter_arrival_long = kwargs.get("inter_arrival_long")
        inter_arrival_short = kwargs.get("inter_arrival_short")


        self.log_message( message=input_message, log_file_name=log_file_name )


        binary_message = self.convert_string_message_to_binary(input_message)


        for bit in binary_message:
            orig_timestamp = self.ntp_timestamp()

            # Create an NTP packet with timestamps
            ntp = NTP(
                version=4,       # NTP version 4
                mode=3,          # Client mode
                stratum=0,       # Stratum (unspecified)
                poll=0,          # Default poll interval
                precision=-20,    # Default precision
                orig=orig_timestamp
            )

            # Build the full packet
            ip = IP(dst="receiver")  # Replace with your desired destination IP
            udp = UDP(sport=123, dport=123)
            pckt = ip / udp / ntp

            # Send pckt first to set prev time in receiver
            super().send(pckt)

            if(bit == "1"):
                time.sleep(inter_arrival_short)
            else:
                time.sleep(inter_arrival_long)
            
        # Send one additional package to complete the communication
        orig_timestamp = self.ntp_timestamp()

        # Create an NTP packet with timestamps
        ntp = NTP(
            version=4,       # NTP version 4
            mode=3,          # Client mode
            stratum=0,       # Stratum (unspecified)
            poll=0,          # Default poll interval
            precision=-20,    # Default precision
            orig=orig_timestamp
        )

        # Build the full packet
        ip = IP(dst="receiver")  # Replace with your desired destination IP
        udp = UDP(sport=123, dport=123)
        pckt = ip / udp / ntp

        super().send(pckt)






    def receive(self, **kwargs):
        log_file_name = kwargs.get("log_file_name", "receiver.log")
        inter_arrival_threshold = kwargs.get("inter_arrival_threshold")
        stop_sniffing = {"stop": False}
        previous_timestamp = None
        decoded_message = []
        received_bits = []

        def process_packet(packet):
            nonlocal previous_timestamp
            nonlocal decoded_message

            if NTP in packet:
                current_orig = packet[NTP].orig

                if previous_timestamp is not None:
                    # Calculate the time difference
                    difference = current_orig - previous_timestamp
                    print(f"Time difference: {difference} seconds")

                    # Determine the bit based on the threshold
                    if difference > inter_arrival_threshold:
                        bit = "0"
                    else:
                        bit = "1"

                    received_bits.append(bit)

                    if(len(received_bits) == 8):
                        
                        print(received_bits)
                        result = ''.join(received_bits)
                        print(result)
                        char = self.convert_eight_bits_to_character(result)
                        print(char)
                        decoded_message.append(char)
                        received_bits.clear()

                        if(char == "."):
                            stop_sniffing["stop"] = True


                # Update the previous timestamp
                previous_timestamp = current_orig

        sniff(
            filter="udp and port 123",  # Filter for NTP packets
            prn=process_packet,
            stop_filter=lambda x: stop_sniffing["stop"]
        )

        # Convert the decoded binary message to a string
        binary_message = "".join(decoded_message)
        # Log the received message
        self.log_message(message=binary_message, log_file_name=log_file_name)





