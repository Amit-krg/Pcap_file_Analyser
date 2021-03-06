Used jnetpcap.jar file to extract the packet from pcap file

Steps to compile:

For Windows:

java -cp .;jnetpcap.jar PcapTcpAnalysis.java

For Linux:

java -cp .:jnetpcap.jar PcapTcpAnalysis.java

To run the program

For Windows:
java -cp .;jnetpcap.jar PcapTcpAnalysis <Pcapfile name>

For Linux:
java -cp .:jnetpcap.jar PcapTcpAnalysis <Pcapfile name>


Overview:
========
 To determine the number of distinct flow initiated from the source I have created a hashmap whose key value is the combination of source port and destination port. Total number of flows will then be the size of the hashmap.
 
  To determine the window size for each flow was tricky, since the window size bit doesn't specify the exact size of the window in terms of bytes, I have read the option field from TCP data to determine the scaling factor which was 14, using which I predicted the window size. For Ack number and sequence number I have stored them for each flow.
  
  The sequence number is the packet number sender uses to inform destination about the order. Sequence number are generated by adding the size of the tcp payload in the last sequence number. On proper reception receiver updates its sequence number for the next packet and acknowledges the last packet received from the sender using the ack field.
 
  To determine the empirical throughput, I have computed the size of all the packets for a particular flow sent from the source to the destination and calculated the time difference between first sent packet and last received packet for that particular flow. Throughput then be  Total Data/(Time difference between first and last packet).
  
  To Calculate the loss, I keep a hashmap where key is the sequence number of the packet sent by the source and value is the acknowledgement counter. If a particular sequence key hit the hash map again, I have considered it as case of packet loss and it is where I increase my packet loss counter.
  Therefore loss rate is (  loss counter )/(loss counter+ size of hashmap of seq key).
  
  To calculate the average RTT. I have taken the time difference between  sent/ack packets over the entire flow and at the end took the average. In case of packet loss, the sent time will be taken of the most recent packet that has been sent. Similarly, In case of duplicate acknowledgement, the receiver time is taken of the very first packet.
  
Results:
=======

Results are Present in output.txt. For theoretical throughput, I have used  (sqrt(3,2)* MSS) /rtt* sqrt(estimated loss)
