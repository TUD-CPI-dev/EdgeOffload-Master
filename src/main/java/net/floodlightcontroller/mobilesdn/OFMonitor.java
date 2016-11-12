/**
*    Copyright 2013 University of Helsinki
*
*    Licensed under the Apache License, Version 2.0 (the "License"); you may
*    not use this file except in compliance with the License. You may obtain
*    a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
*    Unless required by applicable law or agreed to in writing, software
*    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
*    License for the specific language governing permissions and limitations
*    under the License.
**/


package net.floodlightcontroller.mobilesdn;

import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import org.projectfloodlight.openflow.protocol.OFPortStatsEntry;
import org.projectfloodlight.openflow.protocol.OFPortStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class designed for monitoring switch's OpenFlow table
 *
 * The flow table info can be used for later usage
 *
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */

public class OFMonitor implements Runnable {

    protected static Logger log = LoggerFactory.getLogger(OFMonitor.class);

    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;
    private Master master;

    // private List<OFFlowStatisticsReply> statsReply;
    private Timer timer;
    private double interval;
    private int maxNum;
    private List<SwitchOutQueue> swQueueList;

    // default max rate threshold
    static private final double RATE_THRESHOLD = 5000000;
    private double QUEUE_THRESHOLD = 0.7; // 70% * bandwidth
    private int PENDING_TIMEOUT = 4;  // 4s

    // monitoring info is gathered by using a timer
    private class OFMonitorTask extends TimerTask {
        public void run() {
            // flowStatistics();
            // portStatistics();
            portStatisticsForEachAP();
        }
    }

    public OFMonitor(IFloodlightProviderService fProvider, IOFSwitchService fSwitch,Master m,
            double detectInterval, int maxNum, List<SwitchOutQueue> swList) {
        this.floodlightProvider = fProvider;
        this.switchService = fSwitch;
        this.master = m;

        this.timer = new Timer();
        this.interval = detectInterval;
        this.maxNum = maxNum;
        this.swQueueList = swList;
    }


    @Override
    public void run() {
        // start the timer with our task
        timer.schedule(new OFMonitorTask(), (long)5000, (long)(this.interval*1000));
    }

    //find that not in use
    /*private void portStatistics() {
        List<OFStatistics> values = null;
        Future<List<OFStatistics>> future;
        OFPortStatisticsReply reply;

        for (SwitchOutQueue swQueue: swQueueList) {
            IOFSwitch sw = floodlightProvider.getSwitch(swQueue.getSwId());

            OFStatisticsRequest req = new OFStatisticsRequest();
            req.setStatisticType(OFStatisticsType.PORT);
            int requestLength = req.getLengthU();
            OFPortStatisticsRequest specificReq = new OFPortStatisticsRequest();
            specificReq.setPortNumber((short)swQueue.getOutPort());
            req.setStatistics(Collections.singletonList((OFStatistics)specificReq));
            requestLength += specificReq.getLength();
            req.setLengthU(requestLength);

            try {
                // make the query
                future = sw.queryStatistics(req);
                values = future.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.error("Failure retrieving port statistics from switch " + sw, e);
            }

            if (values != null) {
                double rateLimit = QUEUE_THRESHOLD * swQueue.getBandwidth() * 1000000;
                for (OFStatistics stat: values) {
                    reply = (OFPortStatisticsReply) stat;

                    long receiveBytes = reply.getReceiveBytes();
                    long transmitBytes = reply.getTransmitBytes();

                    double downrate = (receiveBytes - swQueue.getReceiveBytes()) / (this.interval);
                    // float uprate = (transmitBytes - swQueue.getTransmitBytes()) / (this.interval);

                    if (downrate*8 >= rateLimit && swQueue.getDownThroughputOverNum() == 0) {
                        long endtime = System.currentTimeMillis();
                        if (master.startTime != 0) {
                            log.debug("Found delay: " + (endtime - master.startTime));
                        } else {
                            log.debug("early found");
                        }
                        master.startTime = endtime;
                    }

                    if (downrate*8 >= rateLimit) {
                        int num = swQueue.getDownThroughputOverNum();
                        swQueue.setDownThroughputOverNum(++num);
                        if (swQueue.downRate*8 < rateLimit
                            && swQueue.getPendingNum() > 0
                            && (swQueue.downRate + downrate) * 8 / 2 >= rateLimit) {
                            // fluctuation probably caused by OF statistics
                            swQueue.setDownThroughputOverNum(++num);
                        }
                        swQueue.setPendingNum(0);
                    } else if (swQueue.getDownThroughputOverNum() > 0) {
                        int pendingNum = swQueue.getPendingNum() + 1;
                        if (pendingNum > Math.ceil(PENDING_TIMEOUT / interval)) {
                            swQueue.setPendingNum(0);
                            swQueue.setDownThroughputOverNum(0);
                        } else {
                            swQueue.setPendingNum(pendingNum);
                        }
                    } else {
                        swQueue.setDownThroughputOverNum(0);
                    }

                    if (swQueue.getDownThroughputOverNum() >= maxNum) {
                        log.info("reach switchqueue port download threshold!!!");
                        master.switchQueueManagement(sw, swQueue);
                        swQueue.setDownThroughputOverNum(0);
                        swQueue.setPendingNum(0);
                        long t = System.currentTimeMillis();
                        log.debug("Detecting delay: " + (t - master.startTime));
                        master.startTime = 0;
                    }

                    log.debug((downrate * 8) + " " + swQueue.getDownThroughputOverNum());

                    swQueue.setReceiveBytes(receiveBytes);
                    swQueue.settransmitBytes(transmitBytes);
                    swQueue.downRate = downrate;
                }
            }
        }
    }
    */
    
    private void portStatisticsForEachAP() {
    	
    	Future<List<OFStatsReply>> future;
    	List<OFStatsReply> values;
    	
    	if ((master.getAllAPAgents()).isEmpty()) {
            return;
        }

    	for (APAgent agent : master.getAllAPAgents()) {
    		IOFSwitch sw = agent.getSwitch();
    		
    		OFStatsRequest req = sw.getOFFactory().buildPortStatsRequest()
                    .setPortNo(OFPort.of(agent.getOFPort()))
                    .build();
    		
    		
    	try {
    		future =  sw.writeStatsRequest(req);    		
		    values = future.get(3, TimeUnit.SECONDS);
    	
    	
    	if (values != null) {
			for (OFStatsReply r : values) {
    		    OFPortStatsReply psr = (OFPortStatsReply) r;
                  
    			for (OFPortStatsEntry pse : psr.getEntries()) {
    				//TODO 和port可以匹配么？
    				long upBytes = pse.getRxBytes().getValue();//接收数据
                    long downBytes = pse.getTxBytes().getValue();//发出数据

                    
                    double downrate = (downBytes - agent.getOFDownBytes()) / (this.interval);
                    log.info("OFMonitor Download rate:"+downrate);
                    if (downrate*8 >= RATE_THRESHOLD) {
                        int num = agent.getDownRateOverNum();
                        agent.setDownRateOverNum(++num);
                        if (agent.getOFDownRate()*8 < RATE_THRESHOLD
                            && agent.getPendingNum() > 0
                            && (agent.getOFDownRate() + downrate) * 8 / 2 >= RATE_THRESHOLD) {
                            // fluctuation probably caused by OF statistics
                            agent.setDownRateOverNum(++num);
                        }
                        agent.setPendingNum(0);
                        log.info("Agent " + agent.getSSID() + " got large traffic load: " 
                                + (downrate * 8) + " " + agent.getDownRateOverNum());
                    } else if (agent.getDownRateOverNum() > 0) {
                        int pendingNum = agent.getPendingNum() + 1;
                        if (pendingNum > Math.ceil(PENDING_TIMEOUT / interval)) {
                            agent.setPendingNum(0);
                            agent.setDownRateOverNum(0);
                        } else {
                            agent.setPendingNum(pendingNum);
                        }
                    } else {
                        agent.setDownRateOverNum(0);
                    }

                    if (agent.getDownRateOverNum() >= maxNum) {
                        // agent.setOffloadingFlag(true);
                        master.agentTrafficManagement(sw, agent);
                        agent.setDownRateOverNum(0);
                        agent.setPendingNum(0);
                    }

                    log.debug("Agent " + agent.getSSID() + ": " + (downrate * 8) 
                            + " " + agent.getDownRateOverNum());
                    agent.setOFDownBytes(downBytes);
                    agent.setOFUpBytes(upBytes);
                    agent.setOFDownRate(downrate);
                   
                	  
                  }
    		  }
    	
         }
    	} catch (Exception e) {
    		log.error("Failure retrieving port statistics from switch " + sw, e);
    	}
      }
    }
   
}

    /**
     * Get flow statistics from switch by using OFFlowStatisticsRequest
     *
     */
    //find that not in use
    // FIXME: currently the OFFlowStatisticsRequest can only use IN_PORT,
    // DL_SRC, DL_DST and DL_VLAN_PCP to match flows, using other fields can
    // only get an empty stats reply. In addition, the match in the reply
    // only contains those four tuples
    // This might be a bug of Floodlight???
/*
    private void flowStatistics() {
        // statsReply = new ArrayList<OFFlowStatisticsReply>();
        List<OFStatistics> values = null;
        Future<List<OFStatistics>> future;
        OFFlowStatisticsReply reply;
        OFMatch match;
        float rate;
        Ethernet mac;

        // get switch
        Map<Long,IOFSwitch> swMap = floodlightProvider.getAllSwitchMap();


        for (IOFSwitch sw: swMap.values()) {
            try {
                OFStatisticsRequest req = new OFStatisticsRequest();
                req.setStatisticType(OFStatisticsType.FLOW);
                int requestLength = req.getLengthU();
                OFFlowStatisticsRequest specificReq = new OFFlowStatisticsRequest();
                specificReq.setMatch(new OFMatch().setWildcards(Wildcards.FULL));
                specificReq.setTableId((byte)0xff);

                // FIXME match bug
                // for example, this can not work here
                // match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)

                // using OFPort.OFPP_NONE(0xffff) as the outport
                specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
                req.setStatistics(Collections.singletonList((OFStatistics) specificReq));
                requestLength += specificReq.getLength();
                req.setLengthU(requestLength);

                // make the query
                future = sw.queryStatistics(req);
                values = future.get(3, TimeUnit.SECONDS);

                if (values != null) {
                    for (OFStatistics stat: values) {
                        // statsReply.add((OFFlowStatisticsReply) stat);

                        reply = (OFFlowStatisticsReply) stat;
                        rate = (float) reply.getByteCount()
                                  / ((float) reply.getDurationSeconds()
                                  + ((float) reply.getDurationNanoseconds() / 1000000000));
                        match = reply.getMatch();

                        // actions list is empty means the current flow action is to drop
                        if (rate >= RATE_THRESHOLD && !reply.getActions().isEmpty()) {

                            mac = new Ethernet().setSourceMACAddress(match.getDataLayerSource())
                                                .setDestinationMACAddress(match.getDataLayerDestination());

                            log.info("Flow {} -> {}", mac.getSourceMAC().toString(),
                                                      mac.getDestinationMAC().toString());

                            log.info("FlowRate = {}bytes/s: suspicious flow, " +
                                    "drop matched pkts", Float.toString(rate));

                            // modify flow action to drop
                            setOFFlowActionToDrop(match, sw);
                        }
                    }
                }


            } catch (Exception e) {
                log.error("Failure retrieving flow statistics from switch " + sw, e);
            }
        }
    }
*/
    /**
     * Modify the action of open flow entries to drop
     *
     * @param match match info obtained from OFFlowStatisticsReply
     * @param sw corresponding OpenFlow switch
     */
    //find that not in use
/*
    private void setOFFlowActionToDrop(OFMatch match, IOFSwitch sw) throws UnknownHostException {

        OFFlowMod flowMod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
        // set no action to drop
        List<OFAction> actions = new ArrayList<OFAction>();

        // set flow_mod
        flowMod.setOutPort(OFPort.OFPP_NONE);
        flowMod.setMatch(match);
        // this buffer_id is needed for avoiding a BAD_REQUEST error
        flowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        flowMod.setHardTimeout((short) 0);
        flowMod.setIdleTimeout((short) 20);
        flowMod.setActions(actions);
        flowMod.setCommand(OFFlowMod.OFPFC_MODIFY_STRICT);

        // send flow_mod
        if (sw == null) {
            log.debug("Switch is not connected!");
            return;
        }
        try {
            sw.write(flowMod, null);
            sw.flush();
        } catch (IOException e) {
            log.error("tried to write flow_mod to {} but failed: {}",
                        sw.getId(), e.getMessage());
        } catch (Exception e) {
            log.error("Failure to modify flow entries", e);
        }
    }
*/


