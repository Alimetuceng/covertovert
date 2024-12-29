
# Covert Timing Channel using Packet Inter-Arrival Times [CTC-PIT-NTP]

This repository presents an implementation of a **Covert Timing Channel (CTC) exploiting Packet Inter-Arrival Times (PIT)** for covert communication. The project aims to simulate secure yet undetectable communication over a regular network by encoding data in timing variations between transmitted packets. 


## Table of Contents

- [Introduction](#introduction)
- [Setup and Installation](#setup-and-installation)
- [Project Workflow](#project-workflow)
- [Implementation Details](#implementation-details)
- [Usage Instructions](#usage-instructions)
- [Covert Channel Capacity](#covert-channel-capacity)


---

## Introduction

A **Covert Channel** is a method of communication that bypasses normal security controls and is used to transmit information in ways that were not originally intended or authorized. 

Unlike legitimate communication channels, covert channels exploit side effects or unused portions of a system,  such as timing delays, hidden data fields, or unconventional use of protocols to encode and transfer information between parties. This project focuses on **timing-based covert channels exploiting packet inter-arrival times**.



Covert channels are categorized into:

1. **Covert Timing Channels:** Manipulate timing delays between packet transmissions to encode data.
2. **Covert Storage Channels:** Exploit unused or unconventional storage fields within network packets.

### Packet Inter-Arrival Times
In this project, timing intervals between consecutive packets encode binary data. For example:
- A delay of less than 10ms represents `1`
- A delay of more than 10ms represents `0`

---

## Setup and Installation

1. **Install Prerequisites**:
   - Docker 

2. **Clone Repository**:
   ```
   git clone https://github.com/Alimetuceng/covertovert.git
   cd https://github.com/Alimetuceng/covertovert.git
   ```

3. **Start Docker Containers**:
   ```bash
   docker compose up -d
   ```

4. **Access Containers**:
	Opening seperate terminals for sender and receiver is suggested.
	Start docker containers on each terminal: 
   - **Sender**: `docker exec -it sender bash`
   - **Receiver**: `docker exec -it receiver bash`

5. **Shared Development Folder**:
   -  `code` folder on local machine is mapped to `/app` in the containers. 

---

## Project Workflow

1. **Fork and Clone**: Start by forking the repository and cloning it locally.
2. **Environment Setup**: Ubuntu 22.04 Docker instance (python3.10.12 and scapy installed).
3. **Implementation**:
   - Develop the sender and receiver components in the `MyCovertChannel` class.
   - Use Scapy and standard python modules for packet manipulation.
4. **Testing**:
   - Use the `make` commands provided to send, receive, and compare messages.
   - After running the Ubuntu Docker, you can type "ip addr" or "ifconfig" to see your network configuration.

---

## Implementation Details

### Covert Timing Channel

This implementation uses the **Packet Inter-Arrival Time (PIT)** technique:
- **Sender**: Encodes binary data in timing intervals between consecutive NTP packets.
- **Receiver**: Decodes the timing intervals to reconstruct the original message.

In regular systems, NTP ( Network Time Protocol) packages are used among host machines and NTP servers . Host machines send time queries to a common NTP server to have a synchronized clock.

This covert channel implementation exploits the origin_timestamp fields of NTP packages to encode message bits instead of carrying out real time data. Acting to routers as if host requested an NTP package while carrying the hidden message inside its field.



Key files include:
- **`MyCovertChannel.py`**: Extends ConvertChannelBase class defined in ConvertChannelBase.py file. Implements the sender and receiver logic.
- **`config.json`**: Contains the parameters that send and receive functions require to function properly:



## Usage Instructions

1. **Configure Parameters**:
   - Update `config.json` with necessary parameters:
   
    ```json
     {
		"covert_channel_code": "CTC-PIT-NTP",
		"send": {
				"parameters": {
						// File to save sender logs
						"log_file_name": "sender.log", 

						// Message to be sent to receiver
						"message": "0123456789 abcdefg.",

						// Intervals to determine bits 
						"inter_arrival_short": 0.001, // for 1
						"inter_arrival_long": 0.06, // for 0
	
						// Receiver IP ( Interpreted by container DNS config)
						"dest_ip":"receiver"
					}
			},
		"receive": {
			"parameters": {
	
					// File to save receiver logs
					"log_file_name": "receiver.log",

					// Threshold value between short and long interval values
					"inter_arrival_threshold": 0.04
				}
			}
		} 
	```



2. **Run Communication**:
   - Start the receiver:
     ```bash
     root@receiver:/app# make receive
     ```
   - Start the sender:
     ```bash
     root@sender:/app# make send
     ```

3. **Verify Results**:
   - Compare logs to validate successful communication:
     ```bash
     root@receiver:/app# make compare
     ```

---

## Covert Channel Capacity

To evaluate channel performance:
1. Transmit a 128-bit message.
2. Measure the time taken to send all packets. ( By Uncommenting the lines in MyConvertChannel.py: start_time, end_time )
3. Compute capacity: 
   ```
   Capacity (bps) = 128 / Time (s)
   ```

### Observed Capacity
- The measured covert channel capacity is **10.678 bps** under standard network conditions.

---
