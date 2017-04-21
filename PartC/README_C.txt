I have used three different programs to solve respective parts of the assignment.
1.AnalysisPcapHttp.java
2.PartC2.java
3.PartC3.java

Steps to compile:

For Windows:

java -cp .;jnetpcap.jar AnalysisPcapHttp.java

For Linux:

java -cp .:jnetpcap.jar AnalysisPcapHttp.java

To run the program

For Windows:
java -cp .;jnetpcap.jar AnalysisPcapHttp <Pcapfile name>

For Linux:
java -cp .:jnetpcap.jar AnalysisPcapHttp <Pcapfile name>

Overview:
=======

Command used to capture the pcap file is 

TCPDUMP port <8092,8093,8094> -w <filename.pcap>

 To Reassemble the HTTP request/response pair I have used a Map which maps the (req & res) to specific combination of port(source+destination). To extract the HTTP header. I have decoded the bytes from the TCP data segment till the delimiter and converted it into the string.
 
 To identify the HTTP protocol, I used the fact that the HTTP 1.0 is non-persistent, HTTP 1.1 is persistant and HTTP 2.0 will not have many parallel connection request.
 To identify HTTP 1.0 I have counted the number of FINs, if it is unusually large I have considered that flow as HTTP 1.0.
 If there are multiple connection request will less number of FINs I have marked that pcap as HTTP1.1. and for HTTP 2.0 number of connection is one.
 
 

Results:
=====

a) Please check the output1.txt.

b)As per the logic I used, I found that http_8092.pcap was using HTTP 1.0, http_8093.pcap was using HTTP1.1 and http_8094.pcap was using HTTP2.0

c) In the third part I found that site loaded faster with HTTP 1.0 and slowest with HTTP1.1. Http 1.0 exchanged more number of packets (i.e 2558).  The least number of packets are sent by http_8094.pcap[which was using HTTP2.0]
 Output is present in output3.txt.
 I  have taken the time from the first packet's timestamp to the last packet's timestamp. I think this result will vary depending on the pcap file.
