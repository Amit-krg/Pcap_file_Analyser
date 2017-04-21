import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PartB {

	Map<Long, Helper> flow = new HashMap<Long, Helper>();
	int totalLost;
	int cFactor;
	
	public static void main(String[] args) {

		PartB obj = new PartB();
		obj.generateReport(args[0]);
	}

	public void generateReport(String fi) {
		
		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		totalLost=0;
		cFactor=0;
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}

		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			
			public void nextPacket(PcapPacket packet, String user) {
					
					int flagVal = packet.getUByte(47);
					
					long seqNo = 0;
					seqNo = (long) packet.getUByte(38);
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(39));
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(40));
					seqNo = (long) (seqNo * Math.pow(16, 2) + packet.getUByte(41));

					long ackNo = 0;
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
						flow.put(sumPort, cObj);
					} 
					else {
						cObj = flow.get(sumPort);
						
					}
					if (cObj.flag) {
						cObj.startTime = packet.getCaptureHeader().timestampInMillis();
						cObj.flag = false;
					}

					if(flagVal==0x10 && srcP==cObj.srcP ){
						
						//if seq is not present in the cObj, new one insert 
						if(!cObj.seqSet.containsKey(seqNo))
							{
								cObj.size +=packet.size();
								//if(cFactor>=0)
									cObj.congCounter++;
								List<Long> obj= new ArrayList();
								obj.add(0l); // 0 Literal								
								cObj.seqSet.put(seqNo,obj);																
							}
								else{
										cObj.lostPackets+=1;
										List obj =cObj.seqSet.get(seqNo);
										
								}
						
							}
					//Ack received from sender
					else if(flagVal==0x10 && srcP!=cObj.srcP){
						try{
								cObj.congWin.add(cObj.congCounter);
								cObj.congCounter--;
							 	List obj =cObj.seqSet.get(ackNo);
							 	if((long)obj.get(0)==0){
							 	obj.add(0,1l);   //updated the first ack						
								cObj.seqSet.put(ackNo,obj);
							 	}
							 	//case where an ack is already received case of duplicate ack
							 	else{
							 		 obj.set(0,(long)obj.get(0)+1);
							 		}
							 	}
							 	
						catch(Exception e){
							//System.out.println("This shouldnt have happened");
						}
					}
					
								
				}	
					};

		try {
			pcap.loop(-1, jpacketHandler, "PCAP_ANAlYSIS");
			
			Helper c;
			int i=0;
			Iterator entries = flow.entrySet().iterator();
			while (entries.hasNext()) {
				int tdaCount=0;
				Entry thisEntry = (Entry) entries.next();
				c = (Helper) thisEntry.getValue();
				System.out.println("TCP Connection " + (++i)+" Source Port:"+c.srcP);
				for(Map.Entry<Long,List<Long>> entry : c.seqSet.entrySet())
				{
					if(entry.getValue().get(0)>=3)
						tdaCount++;
					
				}
				System.out.print("Congestion window: ");
				for(int j=0;j<5;j++)
				{
					try{
						System.out.print(c.congWin.get(j)+", ");
					}catch(Exception e)
					{
						System.out.println("less than five congestion window in the flow");
						break;
					}
				}
				System.out.println("\nTotal triple duplicate acknowledgement :"+tdaCount);
				System.out.println("Total retransmission due to timeout :"+ (c.lostPackets-tdaCount));
				System.out.println("*********************************************");
			} //end of while

			
			
		} 
		finally {
			pcap.close();
		}
	}	
}
	