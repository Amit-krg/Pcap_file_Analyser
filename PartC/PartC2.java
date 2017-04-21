import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
/*
 * if more number of fins are present then HTTP1.0
 * if less fins but more ports are present then HTTP 1.1
 * if only one flow is present then HTTP 2.0
 */
public class PartC2 {

	Map<Long, Helper> portMap = new HashMap<Long, Helper>();
	
public void generateReport(String fi) {
		
		String FILENAME = fi;
		final Map<Long,List<Long>> portMap = new HashMap();
		StringBuilder errbuf = new StringBuilder();
		final int[] finCount={0};
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}

		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			public void nextPacket(PcapPacket packet, String user) {
				 
				int flagVal = packet.getUByte(47);
				long srcP = packet.getUByte(34);
            	srcP = (long) (srcP * Math.pow(16, 2) + packet.getUByte(35));
				long destP = packet.getUByte(36);				
				destP = (long) (destP * Math.pow(16, 2) + packet.getUByte(37));
				long sumPort = srcP + destP;
				
				//if flag is syn
				//keep a mapping with 0-ack awaited and 1 will denote sourcePort
				if(flagVal==2){
					
					if (!portMap.containsKey(sumPort)) {
						List obj=new ArrayList<Long>();
						obj.add(0l);
						obj.add(srcP);
						
						portMap.put(sumPort, obj);
						
					} 
					else {

							System.out.println("retransmission case");
						}			
				
						}
				try{
				List obj=portMap.get(sumPort);
				if((flagVal==16 || flagVal==18)&& flagVal!=17 && srcP != (long)obj.get(1))
				{
					//System.out.println("Src Port:"+srcP+"Dest Port"+destP+ "FlagVal:"+flagVal);
					
							if( 0== (long)obj.get(0))
						{
							obj.set(0, 1l);
						}
						else {
							//flagHTTP1[0]=false;
							//System.out.println("flag for HTTP1 set to false");
					}	
				}
				}catch(Exception e)
				{
					System.out.println("acck after fin");
				}
				
			if(flagVal ==17)
			{
				finCount[0]++;
				portMap.remove(sumPort);
			}
			
		}
			
	};
	
	pcap.loop(-1, jpacketHandler, "Type Analysis");
	//number of fins are more than 3
	if(finCount[0]>2)
		System.out.println(" HTTP type could be : HTTP 1.0");
	else if(portMap.size()==1)
		System.out.println(" HTTP type could be : HTTP 2.0");
	else
		System.out.println(" HTTP type could be : HTTP 1.1");
	
		
} //generateReport
	
	public static void main(String[] args) {

		PartC2 obj = new PartC2();
		System.out.println("opening file"+args[0]);
		obj.generateReport(args[0]);
	}

	
	
}//class end	
	