
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;


class Helper {

	boolean flag;   //to track of starting packet
	long size,startTime,endTime,pStartTime;
	int lostPackets,counter,congCounter;
	long srcP;
	int scalingFactor=0; //scaling factor for window size
	Map<Long, List<Long>> seqSet; // sequence no mapped with [ack,time]
	List<Long> winSet; //To hold the window size of source
	List<Long> sack;	//To hold the source ack no
	List<Long> destPack; //to hold all the information of destination
	List<Integer> congWin;
	public Helper()
	{
		this.flag=true; 
		this.seqSet= new HashMap<Long,List<Long>>();
		this.lostPackets=0;
		this.size=0;
		this.counter=0;
		this.congCounter=0;
		this.congWin=new ArrayList();
		this.winSet=new ArrayList();
		this.sack= new ArrayList();
		this.destPack=new ArrayList();
		this.startTime=0;
		this.endTime=0;
		
	}
}
public class PcapTcpAnalysis {

	boolean oflag=true;
	protected long startTime = 0, endTime = 0;
	long tStamp=0;	
	Map<Long, Helper> flow = new HashMap<Long, Helper>();
	double throughput=0,tThroughput;
	int MSS=1460;
	public static void main(String[] args) {

		PcapTcpAnalysis obj = new PcapTcpAnalysis();
		System.out.println(args[0]);
		obj.generateReport(args[0]);
	}

	public void generateReport(String fi) {

		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();

		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}

		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			
			public void nextPacket(PcapPacket packet, String user) {
										
					int flagVal = packet.getUByte(47);
					
					long seqNo,ackNo;
					
					seqNo = (long) packet.getUByte(38);
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(39));
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(40));
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(41));
					ackNo = (long) packet.getUByte(42);
					ackNo = (long) (ackNo * Math.pow(16, 2) + packet.getUByte(43));
					ackNo = (long) (ackNo * Math.pow(16, 2) + packet.getUByte(44));
					ackNo = (long) (ackNo * Math.pow(16, 2) + packet.getUByte(45));

					long srcP = packet.getUByte(34);
	            	srcP = (long) (srcP * Math.pow(16, 2) + packet.getUByte(35));
					long destP = packet.getUByte(36);				
					destP = (long) (destP * Math.pow(16, 2) + packet.getUByte(37));
					
					
					long sumPort = srcP + destP;
					Helper cObj = null;
					
					if (!flow.containsKey(sumPort)) {
						cObj = new Helper();
						cObj.srcP=srcP;
						cObj.flag=true;
						flow.put(sumPort, cObj);
					} 
					else {
						cObj = flow.get(sumPort);
						
					}
					//if syn packet then get the scaling factor
					if(flagVal==2)
					{
						cObj.scalingFactor=packet.getUByte(73);
					}
					if (cObj.flag) {
						cObj.startTime = packet.getCaptureHeader().timestampInMillis();
						//System.out.println("start"+cObj.startTime);
						cObj.flag = false;
					}
					cObj.endTime = packet.getCaptureHeader().timestampInMillis();
					
					
				if(flagVal==0x10 && srcP==cObj.srcP ){
					
					//if seq is not present in the cObj, new one insert 
					if(!cObj.seqSet.containsKey(seqNo))
						{
							//System.out.println("packet is sent");	
							cObj.size +=packet.size();
							List<Long> obj= new ArrayList();
							obj.add(0l); // 0 Literal
							obj.add(packet.getCaptureHeader().timestampInMillis());
							cObj.seqSet.put(seqNo,obj);
							
							//To keep 2 window and seq number
							if(cObj.counter<2)
							{
								cObj.sack.add(ackNo);
								long winSize=0;
								winSize = (long) packet.getUByte(48);
								winSize = (long) (winSize * Math.pow(16, 2) + packet.getUByte(49));
								winSize=(long) (winSize*Math.pow(2, cObj.scalingFactor));
								cObj.winSet.add(winSize);
							}
							
						}
					//case of repeated sending
							else{
									cObj.lostPackets+=1;
									List obj =cObj.seqSet.get(seqNo);
									obj.add(packet.getCaptureHeader().timestampInMillis()%10000);
									cObj.seqSet.put(seqNo,obj );
							}
					
						}
				else if(flagVal==0x10 && srcP!=cObj.srcP){
					try{
							
						 	List<Long> obj=cObj.seqSet.get(ackNo);
						 	//if packet is not acknowledged yet, ack it and update the round trip time
						 	if((long)obj.get(0)==0)
						 	{						 		
						 	obj.set(0,1l);   //updated the first ack
						 	
						 	obj.add(packet.getCaptureHeader().timestampInMillis());
							//obj.add(1,new Long(tStamp));
							cObj.seqSet.put(ackNo,obj);
						 	
						//storing first 2 flow parameters
						if(cObj.counter<2)
							{
								cObj.destPack.add(seqNo);
								cObj.destPack.add(ackNo);
								long winSize=0;
								winSize = (long) packet.getUByte(48);
								winSize = (long) (winSize * Math.pow(16, 2) + packet.getUByte(49));
								cObj.destPack.add(winSize);
								cObj.counter++;
							}
						 	}
						 	//case where an ack is already received case of duplicate ack
						 	
					}
					catch(Exception e){
						//System.out.println("This shouldnt have happened");
					}
				}
				
							
			}	
					};

		try {
			pcap.loop(-1, jpacketHandler, "PCAP_ANAlYSIS");
			
			System.out.println("Total number of TCP flow initiated from source :"+flow.size());
			
			/*overallTput =overallSize/(overallEndTime- overallStartTime); //bytes/millisecond
			overallTput=overallTput*8/1000; // bits/sec
			
			System.out.println("Overall Throughput is :"+overallTput+" Mbits per second"); */
			
			System.out.println("************************************************************");
			/*start printing Each flow */
			
			int i = 0;
			Iterator entries = flow.entrySet().iterator();
			while (entries.hasNext()) {

				Entry thisEntry = (Entry) entries.next();
				Helper c = (Helper) thisEntry.getValue();
				System.out.println("TCP Connection " + (++i)+"\nSource Port:"+c.srcP);				
				//System.out.println("size is :"+c.size);
				throughput = (double)c.size /(c.endTime-c.startTime) ; 
				throughput=throughput * 8/1000; 
				
				System.out.format("Throughput: %.2f Mbits per second %n",throughput );

				long sum = 0;
				int counter =0,rttC=0;
				for(Map.Entry<Long, List<Long>> entry : c.seqSet.entrySet())
				{
					 List<Long> obj=entry.getValue();
					 				 			 
					 if( (long)obj.get(0)== 1)
					 {
						 int size=obj.size();
						 int val=(int) (obj.get(size-1)-obj.get(size-2));
						 if(val>0 && val<1000)
						 sum+=val;
						 rttC++;
					 }
					if(counter<2)
					{
						System.out.println("Dir -->");
						System.out.print("Seq Number: "+entry.getKey());
						System.out.print(" Ack No: "+c.sack.get(counter));
						System.out.println(" Win Size : "+c.winSet.get(counter));
						System.out.println("<--Dir");
						System.out.print("Seq Number: "+c.destPack.get(3*counter));
						System.out.print(" Ack No: "+c.destPack.get( 3*counter+1));
						System.out.println(" Win Size : "+c.winSet.get(3*counter+2));
						counter++;
					}
				}
				double avgRTT = sum / rttC;
				double lossRate=(double)c.lostPackets/c.seqSet.size();
				System.out.format("Lost rate is :%.5f%n",lossRate);
				System.out.format("Average Round Trip Time: %.5f ms %n",avgRTT);
				try
				{
					tThroughput= ( Math.sqrt(3/2)*MSS)/(avgRTT * Math.sqrt(lossRate));
					tThroughput= tThroughput *8/1000;
					System.out.format("Theoretical throughput is found to be %.3f Mbits per second %n",tThroughput);
				}
				catch(Exception e)
				{
					System.out.println("Theoretical throughput is found to be infinity,loss found to be 0");
				}
				
				

				System.out.println("*************************************************************");
			}

			
			
		} finally {
			pcap.close();
		}

	}

}