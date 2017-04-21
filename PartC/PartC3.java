import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;

public class PartC3{
	boolean flag;
	int pCount;
	long startTime,endTime,totalBytes;
	
	public static void main(String [] args){
		
		PartC3 obj = new PartC3();
		
		obj.generateReport(args[0]);
	}

	public void generateReport(String fi) {

		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		pCount=0;
		totalBytes=0;
		flag=true;
		final Map<Long,Long> portMap=new HashMap();
		System.out.println("Opening file:"+fi);
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
		
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			
			
			public void nextPacket(PcapPacket packet, String user) {
				
				long flagVal=packet.getUByte(47);
				totalBytes+=packet.size();
				pCount++;
				long srcP = packet.getUByte(34);
            	srcP = (long) (srcP * Math.pow(16, 2) + packet.getUByte(35));
				long destP = packet.getUByte(36);				
				destP = (long) (destP * Math.pow(16, 2) + packet.getUByte(37));
				long sumPort = srcP + destP;
				HttpHelper h=null;
				//first packet, make an entry
				if (!portMap.containsKey(sumPort)) {
					
					portMap.put(sumPort, srcP);
					//pCount++;
									} 
				else
					{
						long port=(long)portMap.get(sumPort);
						//if(port==srcP)
							//pCount++;
					}
				if(flag && flagVal==16)
				{
					startTime=packet.getCaptureHeader().timestampInMillis();
					flag=false;
				}
				endTime=packet.getCaptureHeader().timestampInMillis();
				//System.out.println(startTime);
			}
				
											};
										
		pcap.loop(-1, jpacketHandler, "PCAP_ANAlYSIS");
		
		//System.out.println("start"+startTime+" end"+endTime);
		System.out.format("Total time it took to serve the request is:%.3f seconds %n",(double)(endTime-startTime)/1000);
		System.out.println("Total packets exchanged: "+pCount);
		System.out.format("Total Raw Bytes Exchanged: %.3f KB %n",(double)totalBytes/1000);
		}
	
}
