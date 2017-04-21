Used jnetpcap.jar file to extract the packet from pcap file

Steps to compile:

For Windows:

java -cp .;jnetpcap.jar PartB.java

For Linux:

java -cp .:jnetpcap.jar PartB.java

To run the program

For Windows:
java -cp .;jnetpcap.jar PartB <Pcapfile name>

For Linux:
java -cp .:jnetpcap.jar PartB <Pcapfile name>

Overview:
-----------

 I have estimated the congestion window based on the notion that it represent number of unacknowledged packets. I have kept a counter which increments if any packet is sent from sender to the receiver. I also decrement it as soon as an ack is received from the destination.
 
 To estimate nunber of times a transmission occured due to the triple duplicate acknowledgement or timeout, I have used the similar idea as in part A. I have used a hashmap which maps the source +destination port to a helper class object which in turns maintains the ds for each flow. In one of the data structure I'm maintaining the seq numbers and number of times and ack is received for the seq number. If more than one ack are received I increment the respective ack counter.
 At the end I counter all the ack counter whose value is equal to or more than 3, to which I considered as count of TDA.
 
 and for the timedout packets, I calculated it as  (Total_lost in the flow- TDA )

Results:
---------

Result for all the file is present in output.txt