import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;

class HttpHelper{
	Long srcP;
	List<Http> reqRes;
	
	HttpHelper()
	{		
		reqRes=new ArrayList();
	}
}

public class AnalysisPcapHttp{
	public static void main(String [] args){
		
		AnalysisPcapHttp obj = new AnalysisPcapHttp();
		
		obj.generateReport(args[0]);
	}

	public void generateReport(String fi) {

		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		final Http http= new Http();
		final Map<Long,HttpHelper > portMap; // sumport, srcport,res and res
		portMap=new HashMap();
		System.out.println("Opening file:"+fi);
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
		
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			JBuffer buff = new JBuffer(20);
			public void nextPacket(PcapPacket packet, String user) {
				
				if(packet.hasHeader(Http.ID))
				{
					int flagval=packet.getUByte(47);
					long seqNo = 0,ackNo=0;
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
					HttpHelper h=null;
					//first packet, make an entry
					if (!portMap.containsKey(sumPort)) {
						
						//System.out.println("Making entry for"+srcP);
						h=new HttpHelper();
						h.srcP=srcP;
						h.reqRes.add(packet.getHeader(http));
						portMap.put(sumPort, h);
						
					} 
					//response with header
					else {
						//System.out.println("adding for response Port sum:"+sumPort);
						h= portMap.get(sumPort);
						if(srcP!=h.srcP)
						{
							h.reqRes.add(packet.getHeader(http));
						}
						else
							System.out.println("another req from the same port");
					}
					
					
					
				}
			}
				
											};
										
		pcap.loop(-1, jpacketHandler, "PCAP_ANAlYSIS");
		
		for(Map.Entry<Long,HttpHelper> entry : portMap.entrySet())
		{
			HttpHelper h;
			h=entry.getValue();
			
			System.out.println("Source Port:"+h.srcP+" Destination port: "+( (long)entry.getKey()-h.srcP) );
			System.out.println("Req:"+h.reqRes.get(0));
			try{
			System.out.println("Res:"+h.reqRes.get(1));
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
	}
}
