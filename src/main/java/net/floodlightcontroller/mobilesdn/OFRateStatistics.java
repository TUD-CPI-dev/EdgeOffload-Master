package net.floodlightcontroller.mobilesdn;

import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.util.ActionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;

public class OFRateStatistics implements Runnable {
	protected static Logger log = LoggerFactory.getLogger(OFMonitor.class);

    private IFloodlightProviderService floodlightProvider;
    private Master master;
    private Timer timer;
    private double interval;
	
    
    // monitoring info is gathered by using a timer
    private class OFRateStatisticsTask extends TimerTask {
        public void run() {
        	RateStatistics();
        }
    }
    
    public OFRateStatistics(IFloodlightProviderService fProvider, Master m,
            double detectInterval) {
        this.floodlightProvider = fProvider;
        this.master = m;
        this.timer = new Timer();
        this.interval = detectInterval;
    }
	
	@Override
	public void run() {
		timer.schedule(new OFRateStatisticsTask(), (long)5000, 
				(long)(this.interval*1000));
	}
	
	private void RateStatistics() {
		
		Future<List<OFStatsReply>> future;
    	List<OFStatsReply> values;
    	
    	for (APAgent agent: master.getAllAPAgents()) { // Terrible O(n³)
    		
            IOFSwitch sw = agent.getSwitch();
            
            Match.Builder matchBuilder = sw.getOFFactory().buildMatch();
            
            OFStatsRequest req = sw.getOFFactory().buildFlowStatsRequest()
                    .setMatch(matchBuilder.build())
                    .setTableId(TableId.ALL)
                    .setOutPort(OFPort.NO_MASK)
                    .build();
            try {
    	    	
    	    	future =  sw.writeStatsRequest(req); 
    			values = future.get(3, TimeUnit.SECONDS);
    			
    			if (values != null) {
    				double agentUpRateSum = 0;
                    double agentDownRateSum = 0;
                	// calculate rate for each client
                	for (Client clt: agent.getAllClients()) {
                		MacAddress cltMac = clt.getMacAddress();
                		long cltUpByteSum = 0;
                        long cltDownByteSum = 0;
                        
                        for (OFStatsReply r : values) {
    		                OFFlowStatsReply psr = (OFFlowStatsReply) r;
    		                
    		                for (OFFlowStatsEntry pse : psr.getEntries()) {
    		                	long byteCount = pse.getByteCount().getValue();
    		                	//log.info("Test1.2RateStatistics byteCount:"+byteCount);
    		                	if (!ActionUtils.getActions(pse).isEmpty() && byteCount > 0) {
    	                            Match match = pse.getMatch();
    	                            MacAddress dstMac = match.get(MatchField.ETH_DST);
    	                            MacAddress srcMac = match.get(MatchField.ETH_SRC);
    	                            if(dstMac!=null && srcMac!=null){
    	                            	//log.info("Test1.2RateStatistics clientMac:"+cltMac.toString()+"dstMac:"+dstMac.toString()+"srcMac:"+srcMac.toString());
    	                            }
    	                            if (cltMac.equals(dstMac)) {
    	                            	//log.info("Test1.2RateStatistics equal ETH_DST :"+cltMac.toString());
    	                            	cltDownByteSum += byteCount;
    	                                continue;
    	                            } else if (cltMac.equals(srcMac)) {
    	                            	//log.info("Test1.2RateStatistics equal ETH_SRC:"+cltMac.toString());
    	                            	cltUpByteSum += byteCount;
    	                            	continue;
    	                            }
    	                        }    		                	
    		                }
                        }
                        long upByteDiff = cltUpByteSum - clt.getOFUpBytes();
                		long downByteDiff = cltDownByteSum - clt.getOFDownBytes();
                		if (cltUpByteSum < clt.getOFUpBytes()) { // in case of overflow
                			upByteDiff = Long.MAX_VALUE - clt.getOFUpBytes() 
                					+ cltUpByteSum - Long.MIN_VALUE;
                			cltUpByteSum = cltUpByteSum - Long.MIN_VALUE;
                		}
                		if (cltDownByteSum < clt.getOFDownBytes()) {
                			downByteDiff = Long.MAX_VALUE - clt.getOFDownBytes()
                					+ cltDownByteSum - Long.MIN_VALUE;
                			cltDownByteSum = cltDownByteSum - Long.MIN_VALUE;
                		}
                		
                		double upRate = Math.abs(upByteDiff) * 8 / interval;
                		double downRate = Math.abs(downByteDiff) * 8 / interval;
                		
                		clt.updateUpRate(upRate);
                		clt.updateDownRate(downRate);
                		clt.updateOFUpBytes(cltUpByteSum);
                		clt.updateOFDownBytes(cltDownByteSum);
                		agentUpRateSum += upRate;
                		agentDownRateSum += downRate;
                		
                		log.debug("clt rate debug: " + clt.getIpAddress().toString()
                					+ " -- " + upRate + " - " + downRate);
                        
                		
                	}
                	agent.updateUpRate(agentUpRateSum);
                	agent.updateDownRate(agentDownRateSum);   				
    			}
    		} catch (Exception e) {
                    log.error("[ClientRate] Failure retrieving flow statistics from switch " + sw, e);
            }
    	}   	   	   			    
	}	
}
