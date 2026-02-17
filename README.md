# Shielding-the-Grid-Analyzing-C2-Communication-Critical-Infrastructure-Threats-in-an-ICS-Environment
# INPROGRESS

## Objective 

Demonstrate your threat hunting and network traffic analysis skills by uncovering a C2 communications–related incident. On one of the organization’s critical endpoints, a suspicious file with an unusual extension was flagged by security tooling. Analyze the provided network traffic to trace the attacker’s activity and identify the threat.



File Path: /root/Desktop/LD-ICS-FUELSTATION-COMPROMISE.zip

<img width="1172" height="744" alt="image" src="https://github.com/user-attachments/assets/49a11d40-5f73-4328-b06a-86ed296f8fe5" />


## Questions 

1. The Attacker started off by scanning the subnet. When did port scanning activity start?
2. When did the port scanning activity stop?
3. Please identify the IP Address of the internal asset used by the threat actor?
4. Which port other than the tank gauge system was open on the system?
5. Which port was being used by the ICS system?
6. Can you confirm the Vendor of the Automated tank gauge system being used on the field?
7. What is the Name of the petroleum pump that was being attacked?
8. What is the function code used by the attacker for unauthorized access of data for delivery reports?
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

1. The Attacker started off by scanning the subnet. When did port scanning activity start?

The question is asking when the the Attacker sends a massive wave of requests or SYN packets to a range of ports. I was looking for a specific filter to look for TCP Packets,"tcp.flags.syn", which means someone is trying to start a conversation. The "&&" means "And Also". Finally, the TCP.Flags.ack is to make sure they haven't gotten a yes back yet. 

Within Line 34, I can see the attacker sends out the request on "2025-08-27 07:27:31."

<img width="1189" height="732" alt="image" src="https://github.com/user-attachments/assets/ffd13c49-cbae-450d-83aa-9a42eec3347f" />


2. When did the port scanning activity stop?

To find the end time, I looked for the cooldown period. When the massive burst of SYN packets ended, the gap in time before the next set of structured traffic began. I scrolled to the very last packet in that high speed sequence and grabbed the timestamp 2025-08-27 07:27:34.

<img width="1130" height="170" alt="image" src="https://github.com/user-attachments/assets/0f0e3fcf-c1ae-46cb-8ca8-69f1e8bfe08f" />

The IO Graph below shows how fast the attacker ran the port scan. The Y-axis shows how much noise occurred. The X-axis shows the time. I saw a high spike in the graph when the attacker port scan began. When the wave crashed, the graph fell flat.

<img width="1130" height="698" alt="image" src="https://github.com/user-attachments/assets/79ab4090-7462-46c6-a559-00a237f2f4f9" />


3. Please identify the IP Address of the internal asset used by the threat actor?

I looked at the source column. I noticed one specific internal IP Address was the main source. While every other device was minding its own business. This would be the Source Address. 

10.10.32.130

<img width="714" height="374" alt="image" src="https://github.com/user-attachments/assets/ea2b7c06-7e72-4276-b897-8abcac811d4d" />

4. Which port other than the tank gauge system was open on the system?
   
