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
        
        # Initialize from parameters
        input_message = kwargs.get("message")
        log_file_name = kwargs.get("log_file_name", "sender.log")
        inter_arrival_long = kwargs.get("inter_arrival_long")
        inter_arrival_short = kwargs.get("inter_arrival_short")


        # Log the message to be sent 
        self.log_message( message=input_message, log_file_name=log_file_name )
        

        # Convert message to binary message to send bit by bit
        binary_message = self.convert_string_message_to_binary(input_message)


        # For each bit in the message, do step 1, step 2, step 3
        for bit in binary_message:

            # (Step 1) Create an NTP packet with current time
            orig_timestamp = self.ntp_timestamp()
            ntp = NTP(orig=orig_timestamp)
            ip = IP(dst="receiver")  # Replace with your desired destination IP
            udp = UDP(sport=123, dport=123)
            pckt = ip / udp / ntp

            # (Step 2) Send packet to receiver
            super().send(pckt) 
            # Packet is sent before sleep methods to set the  previous_timestamp value reciever


            # (Step 3) Sleep X amount ( long or short ) according to the bit value  
            if(bit == "1"):
                time.sleep(inter_arrival_short)
            else:
                time.sleep(inter_arrival_long)
        

        # Send one more packet to complete the communication


        # Create an NTP packet with current time
        orig_timestamp = self.ntp_timestamp()
        ntp = NTP(orig=orig_timestamp)
        ip = IP(dst="receiver")
        udp = UDP(sport=123, dport=123)
        pckt = ip / udp / ntp

        # Send packet to receiver
        super().send(pckt)


    def receive(self, **kwargs):

        # Initialize from parameters
        log_file_name = kwargs.get("log_file_name")
        inter_arrival_threshold = kwargs.get("inter_arrival_threshold")

        # Sniff stop condition
        stop_sniffing = {"stop": False}

        # Store timestamp of the last package
        previous_timestamp = None

        # List to store the overall decoded message ( ASCII Characters )
        decoded_message = []

        # List to store temporary bit values ( Until the length is 8 )
        received_bits = []

        # Helper nested function to process the packets: 
        def process_packet(packet):
            nonlocal previous_timestamp
            nonlocal decoded_message

            if NTP in packet:
                
                # Get timestamp of captured package 
                current_orig = packet[NTP].orig

                # if it is not the first package, do 
                if previous_timestamp is not None:

                    # (Step 1) Calculate the time difference between current and the former timestamps
                    difference = current_orig - previous_timestamp

                    # Determine the bit based on the difference being under or above the threshold
                    if difference > inter_arrival_threshold:
                        bit = "0"
                    else:
                        bit = "1"

                    # Add the determined bit to received_bits list
                    received_bits.append(bit)

                    # if received_bits has 8 bits, then convert to char and clear the list 
                    if(len(received_bits) == 8):
                        
                        result = ''.join(received_bits)
                        char = self.convert_eight_bits_to_character(result)

                        # Append the char to the decoded_message
                        decoded_message.append(char)

                        # Clear the received_bits list for the next char 
                        received_bits.clear()
                        
                        # if the char is "." , then set sniffing_stop value as true
                        if(char == "."):
                            stop_sniffing["stop"] = True


                # Update the previous timestamp, or set from None if it is the first package
                previous_timestamp = current_orig

        sniff(
            filter="udp and port 123",
            prn=process_packet,
            stop_filter=lambda x: stop_sniffing["stop"]
        )

        # Convert the decoded binary message to a string
        merged_message = "".join(decoded_message)

        # Log the received message
        self.log_message(message=merged_message, log_file_name=log_file_name)

