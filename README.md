# Shielding-the-Grid-Analyzing-C2-Communication-Critical-Infrastructure-Threats-in-an-ICS-Environment
# INPROGRESS

## Objective 

Demonstrate your threat hunting and network traffic analysis skills by uncovering a C2 communications–related incident. On one of the organization’s critical endpoints, a suspicious file with an unusual extension was flagged by security tooling. Analyze the provided network traffic to trace the attacker’s activity and identify the threat.

ICS is an Industrial Control systems, this challenge is about risk management and problem-solving to find the silent signal the hacker was using to give orders to the station's computers and shut it down. I will use Wireshark to create a clear map of what happened. 

File Path: /root/Desktop/LD-ICS-FUELSTATION-COMPROMISE.zip



<img width="1172" height="744" alt="image" src="https://github.com/user-attachments/assets/49a11d40-5f73-4328-b06a-86ed296f8fe5" />


## Questions 

1. The Attacker started by scanning the subnet. When did port scanning activity start?
2. When did the port scanning activity stop?
3. Please identify the IP Address of the internal asset used by the threat actor?
4. Which port other than the tank gauge system was open on the system?
5. Which port was being used by the ICS system?
6. Can you confirm the Vendor of the Automated tank gauge system being used on the field?
7. What is the Name of the petroleum pump that was being attacked?
8. What is the function code used by the attacker for unauthorized access to data for delivery reports?
9. At what time was a leak detected from one of the tanks?
10. What was the status of the 1s product in the inventory?
11. The Attacker got access to the Delivery reports for the station. When was the time for the last delivery?
12. When did the attacker gain access to the site’s shift reports?
13. What was the temperature of the 2nd Gasoline product at the time of the incident?
14. What is the name of the product in the Fourth tank?
15. What was the hostname of the machine running the tank gauge software?
16. The Attacker manipulated the tank gauge values and changed the product names to deliver a message to the organization and staff, demanding a ransom payment. What was the ransom amount demanded by the attacker?
17. What was the email address associated with the attacker?





## STEPS TAKEN

1. The Attacker started by scanning the subnet. When did port scanning activity start?

The question is asking when the the Attacker sends a massive wave of requests or SYN packets to a range of ports. I was looking for a specific filter to look for TCP Packets,"tcp.flags.syn", which means someone is trying to start a conversation. The "&&" means "And Also". Finally, the TCP.Flags. ack is to make sure they haven't gotten a yes back yet. 

Within Line 34, I can see the attacker sends out the request on "2025-08-27 07:27:31."

<img width="1189" height="732" alt="image" src="https://github.com/user-attachments/assets/ffd13c49-cbae-450d-83aa-9a42eec3347f" />


2. When did the port scanning activity stop?

To find the end time, I looked for the cooldown period. When the massive burst of SYN packets ended, the gap in time before the next set of structured traffic began. I scrolled to the very last packet in that high-speed sequence and grabbed the timestamp 2025-08-27 07:27:34.

<img width="1130" height="170" alt="image" src="https://github.com/user-attachments/assets/0f0e3fcf-c1ae-46cb-8ca8-69f1e8bfe08f" />

The IO Graph below shows how fast the attacker ran the port scan. The Y-axis shows how much noise occurred. The X-axis shows the time. I saw a high spike in the graph when the attacker port scan began. When the wave crashed, the graph fell flat.

<img width="1130" height="698" alt="image" src="https://github.com/user-attachments/assets/79ab4090-7462-46c6-a559-00a237f2f4f9" />


3. Please identify the IP Address of the internal asset used by the threat actor?

I looked at the source column. I noticed one specific internal IP Address was the main source. While every other device was minding its own business. This would be the Source Address. 

10.10.32.130

<img width="714" height="374" alt="image" src="https://github.com/user-attachments/assets/ea2b7c06-7e72-4276-b897-8abcac811d4d" />

4. Which port other than the tank gauge system was open on the system?

The tank Gauge is a fuel station ICS environment, and it seems like the attacker opened a backdoor (port) to enter and exploit. 

I would need to change the filter to "tcp.flags.syn == 1 && tcp.flags.ack == 1" 

This works because it will filter out the failed attempt, which is what we looked for previously. Now it will show us the successful attempt or successful handshakes (SYN, ACK).
tcp.flags.syn == 1: "Show me someone trying to start a connection."
&&: "And..."
tcp.flags.ack == 1: "...show me that the computer acknowledged it and said 'Yes'."

After filtering for the TCP three-way handshake, I discovered the successful SYN, ACK response from Port 21, which is used for file transfers. This is a back entrance for the attacker to start exploiting the ICS. 

<img width="1826" height="868" alt="image" src="https://github.com/user-attachments/assets/3fa75744-6a71-42f0-8082-1289a47c9724" />


5. Which port was being used by the ICS system?
The next port that I see being used right after the handshake is 10001. SCP Configuration services and various network management applications commonly use port 10001. This port may be associated with proprietary software configuration interfaces, legacy system administration tools, or custom enterprise applications that require secure file transfer configuration.
Common Risks
Unauthorized configuration access
Weak authentication allows configuration tampering

Information disclosure
Configuration interfaces may leak system details

Privilege escalation
Configuration tools often run with elevated privileges

Remote code execution
Configuration commands may enable arbitrary code execution

Service disruption
Malicious configuration changes can disable critical services.

Credential harvesting
Configuration files may contain stored passwords.

Network segmentation bypass
Management interfaces may provide unintended network access
10001

<img width="1826" height="868" alt="image" src="https://github.com/user-attachments/assets/cc5363f5-2820-4109-a726-8591ebf480d8" />

6. Can you confirm the Vendor of the Automated tank gauge system being used on the field?

After researching online, the FortiGuard website told me that Veeder-Root uses an automated tank gauge system protocol. It is used to monitor fuel inventory levels. ATGs are used by nearly every fueling station in the United States and tens of thousands of systems internationally. The server listens by default on TCP port 10001.

Link: https://www.fortiguard.com/appcontrol/40005

<img width="668" height="116" alt="image" src="https://github.com/user-attachments/assets/0383083e-f4fe-436c-bf07-7cced832b4a1" />

7. What is the Name of the petroleum pump that was being attacked?

I need to start analyzing the TCP traffic from port 10001 of the server running the tank gauge to the attacker machine. I need to analyze the TCP stream and follow it to the interactive session of the attacker with the tank gauge. I can use the following filter "tcp.port == 10001 && tcp.len > 200", which shows any TCP packet with a size greater than 200 from the 10001 port.

tcp.port == 10001: "Only show me the conversation happening on the 'Fuel Tank' channel."
tcp.len > 200: "...only show me packets that are carrying more than 200 bytes of data."

After following the Stream, I can view the TCP Stream of the ICS Fuelstation inventory list. 
The name of the petroleum pump that was being attacked was LD Refinery. 

<img width="952" height="484" alt="image" src="https://github.com/user-attachments/assets/4a0b8c0b-ae0c-45ae-ae47-38d80ea007ea" />


8. What is the function code used by the attacker for unauthorized access to data for delivery reports?

I have the heavy packets filter on, and I just need to look for the right conversation between the packets.  I clicked on the largest packet that I found on port 10001. It was line 2809 with the packet size of 527. I then followed the TCP stream.  
In the TCP stream window, I then noticed that it sent a Delivery report which included sensitive operational data. The response was successful and returned by the tank gauge. The Function Code streams the output: I20200. 

<img width="1233" height="796" alt="image" src="https://github.com/user-attachments/assets/f2304a7a-dd2b-41fd-9d57-5936fa34ed99" />


9. At what time was a leak detected from one of the tanks?

There was more information on the TCP stream, so when I scrolled down, I was able to view certain messages. Tank 1 test status was off, and leaked data was not available on this tank. Tank 2 test status was on, and a leak was detected at 3:14 AM.

<img width="1323" height="698" alt="image" src="https://github.com/user-attachments/assets/b7fed402-5f60-44e7-a64a-389770e609a7" />


10. What was the status of the 1s product in the inventory?

Continuing the stream, it is asking what the status of tank one is. I was able to find that it is filling in progress.


<img width="1184" height="544" alt="image" src="https://github.com/user-attachments/assets/7e44bffd-3a2d-4b46-82e1-3938eb8839e9" />

11. The Attacker got access to the Delivery reports for the station. When was the time for the last delivery?

Following the same stream, I'm able to find out the delivery report and when it ended. 

Answer: 2025-08-27 02:24

<img width="998" height="246" alt="image" src="https://github.com/user-attachments/assets/a697d1a9-6aaa-49ea-a59c-9dc68d561769" />

12. When did the attacker gain access to the site’s shift reports?

If I follow the stream, in the function I200500, the hacker decided to add certain functions to the reports at 2025-08-27 07:35. 
 
"^AS60201YOU_ARE_HACKED
^AS60202PAY_US_50_ETH
^AS60203CONTACT_US_AT
^AS60204LEGIONGROUP@PROTONMAIL.COM
^AI20100"

<img width="1012" height="614" alt="image" src="https://github.com/user-attachments/assets/44276a62-b0d6-4186-a4e3-c171d6ab4bd0" />


13. What was the temperature of the 2nd Gasoline product at the time of the incident?
 After the hacker decided to hack into the ICS. He renamed the tanks, but the tank numbers stayed the same. I followed the stream and was able to locate tank 2, which used to be fuel oil, and looked at the temperature, which is -34.66.


<img width="1064" height="670" alt="image" src="https://github.com/user-attachments/assets/73d67523-7b21-40ea-a654-96750468f772" />


14. What is the name of the product in the Fourth tank?

Before the attacker changed the names of the tanks, it was named JetFuel. 

<img width="1064" height="670" alt="image" src="https://github.com/user-attachments/assets/3f958760-8508-4f3e-90be-fa73d363aab9" />


15. What was the hostname of the machine running the tank gauge software?

To find a hostname, I have to look for the computer that introduced itself to the network. The  DHCP or dynamic host configuration protocol process is basically the orientation for any device. When the computer joins a network, it shouts out hey I'm new here my name is hostname, can I get an IP address. In Wireshark, the filter is simply DHCP. When I apply this to the filter, I'm going to be looking for the DHCP request. Inside the packet, there will be a specific field, and that's where the name of the computer or name tag lives. 

I filtered for DHCP in Wireshark and looked for the DHCP message type and hostname. The host name is "LD-PETROLEUM-SITE-6".

<img width="1300" height="882" alt="image" src="https://github.com/user-attachments/assets/590f382f-ba12-4037-8e28-04dcfab818d2" />


16. The Attacker manipulated the tank gauge values and changed the product names to deliver a message to the organization and staff, demanding a ransom payment. What was the ransom amount demanded by the attacker?


In the previous TCP stream that we followed, at the end of the stream when the attacker renamed the tanks in tank 2, it said pay us 50 ETH. ETH is the Ethereum cryptocurrency.

<img width="950" height="230" alt="image" src="https://github.com/user-attachments/assets/27b3d94b-fcf3-4ecc-85e8-22031afa4ddf" />




17. What was the email address associated with the attacker?

In the same stream, they list the Email address in Tank 4 and in the previous function to, we can read the full email address. Function: ^AS60204LEGIONGROUP@PROTONMAIL.COM"

<img width="1190" height="456" alt="image" src="https://github.com/user-attachments/assets/7e5da0c4-94f9-4ce4-95e2-dbb853ed0a48" />



<img width="792" height="778" alt="image" src="https://github.com/user-attachments/assets/f19b23a5-a722-4c69-b07d-a90578d0b5e9" />

## Learning Experience

I used Wireshark to map attacker activity on critical endpoints involving an incident at a fuel station. I was able to identify port scanning starting at 2025-08-27 07:27:31. I used the filter tcp.flags.syn == 1 && tcp.flags.ack == 0 to isolate connection attempts. This filter shows requests without successful responses. The scan ended at 2025-08-27 07:27:34. The IO Graph confirms a sharp traffic spike followed by a sudden drop. The attacker used the internal IP 10.10.32.130 to pivot through the network. I found the machine hostname by filtering for DHCP traffic. DHCP Option 12 reveals the name LD-PETROLEUM-SITE-6. This machine runs the tank gauge software.

I found Port 21 open on the target. This indicates an FTP service. I filtered for successful handshakes using tcp.flags.syn == 1 && tcp.flags.ack == 1 to find this backdoor. The primary ICS system operates on Port 10001. This port belongs to the Veeder-Root Automated Tank Gauge protocol. I filtered for packets larger than 200 bytes on Port 10001. This revealed the command and control traffic. The attacker used function code I20200 to access sensitive delivery reports. The last recorded delivery occurred on 2025-08-27 02:24.

The attacker manipulated tank gauge values to demand a ransom. They renamed the inventory products to display a message. The demand was 50 ETH sent to LEGIONGROUP@PROTONMAIL.COM. During the breach, the system recorded a leak in Tank 2 at 03:14 AM.
