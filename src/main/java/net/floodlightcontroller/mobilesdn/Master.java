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


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.util.ActionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.LogicalOFMessageCategory;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.mobilesdn.ClickManageServer;
import net.floodlightcontroller.mobilesdn.web.SoftOffloadWebRoutable;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.storage.IStorageSourceListener;
import net.floodlightcontroller.threadpool.IThreadPoolService;



/**
 * This is an implementation of sdn wireless and mobile controller
 *
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 **/

public class Master implements IFloodlightModule, IFloodlightService,
                                  IOFSwitchListener, IOFMessageListener,
                                  IStorageSourceListener, ISoftOffloadService {


    private static class APConfig {
        public String ipAddr;
        public String ssid;
        public String bssid;
        public String auth;
        public short ofPort;
        public double downlinkBW;  // bandwidth

        public APConfig(String ip, String s, String b, String auth, short port, double bw) {
            ipAddr = ip;
            ssid = s;
            bssid = b;
            this.auth = auth;
            ofPort = port;
            downlinkBW = bw;
        }
    }

    private static class SwitchNetworkConfig implements Comparable<Object> {
        public String swIPAddr;
        public int outPort;
        public int bandwidth;
        public List<String> apList;

        public SwitchNetworkConfig(String ip, int port, int w, List<String> ap) {
            swIPAddr = ip;
            outPort = port;
            bandwidth = w;
            apList = ap;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof SwitchNetworkConfig))
                return false;

            if (obj == this)
                return true;

            SwitchNetworkConfig that = (SwitchNetworkConfig) obj;

            return (this.swIPAddr.toLowerCase().equals(that.swIPAddr.toLowerCase())
                    && this.outPort == that.outPort);
        }

        @Override
        public int compareTo(Object arg0) {
            assert (arg0 instanceof SwitchNetworkConfig);

            if (this.swIPAddr.toLowerCase().equals(((SwitchNetworkConfig)arg0).swIPAddr.toLowerCase())) {
                if (this.outPort == ((SwitchNetworkConfig)arg0).outPort) {
                    return 0;
                } else if (this.outPort > ((SwitchNetworkConfig)arg0).outPort) {
                    return 1;
                }
            }

            return -1;
        }
    }

    protected static Logger log = LoggerFactory.getLogger(Master.class);
    protected IRestApiService restApi;

    private IFloodlightProviderService floodlightProvider;
    protected static IOFSwitchService switchService;
    
    private ScheduledExecutorService executor;

    // private NetworkManager networkManager;
    private Map<String, APAgent> apAgentMap = new ConcurrentHashMap<String, APAgent>();
    private List<SwitchOutQueue> swQueueList = new CopyOnWriteArrayList<SwitchOutQueue>();
    private List<SwitchNetworkConfig> networkTopoConfig = new LinkedList<SwitchNetworkConfig>();
    private Map<String, APConfig> apConfigMap = new HashMap<String, APConfig>();
    private Map<String, Client> allClientMap = new ConcurrentHashMap<String, Client>();

    private List<Client> offloadingCandidates = new CopyOnWriteArrayList<Client>();
    
    public boolean enableCellular = false;
    public long startTime = 0;

    // some defaults
    private final int DEFAULT_PORT = 28190;
    private final String DEFAULT_TOPOLOGY_FILE = "networkFile";
    private final String DEFAULT_AP_CONFIG = "apConfig";
    private final double OF_MONITOR_INTERVAL = 2.0;
    private final int OF_MONITOR_MAX_NUM = 10;

    public Master(){
        // networkManager = new NetworkManager();
    }
    
    public synchronized Collection<APAgent> getAllAPAgents() {
        return apAgentMap.values();
    }

    /**
     * Add an agent to the Master tracker
     *
     * @param ipv4Address Client's IPv4 address
     */
    public void addUnrecordedAPAgent(final InetAddress ipv4Address) {

        String ssid;
        String bssid;
        String auth;
        short ofPort;
        double bw;
        String ipAddr = ipv4Address.getHostAddress();
        APAgent agent = new APAgent(ipv4Address);


        if (apConfigMap.containsKey(ipAddr)) {
            APConfig ap = apConfigMap.get(ipAddr);
            ssid = ap.ssid;
            bssid = ap.bssid;
            auth = ap.auth;
            ofPort = ap.ofPort;
            bw = ap.downlinkBW;
            log.info("Init AP from APConfig file: ssid=" + ssid + ", auth=" + auth);
        } else {
            ssid = "";
            bssid = "";
            auth = "";
            ofPort = 0;
            bw = 0;
            log.warn("Unconfiged AP found, initialize it without SSID and BSSID");
        }

        agent.setSSID(ssid);
        agent.setBSSID(bssid);
        agent.setAuth(auth);
        agent.setOFPort(ofPort);
        agent.setDownlinkBW(bw);
        apAgentMap.put(ipAddr, agent);
    }

    /**
     * check whether an agent is in the HashMap
     *
     * @param addr Agent's IPv4 address
     */
    private boolean isAPAgentTracked(InetAddress addr) {
        if (apAgentMap.containsKey(addr.getHostAddress())) {
            return true;
        }

        return false;
    }

    /**
     * Handle a ClientInfo message from an agent.
     *
     * @param agentAddr
     * @param clientEthAddr
     * @param clientIpAddr
     */
    synchronized void receiveClientInfo(final InetAddress agentAddr,
            final String clientEthAddr, final String clientIpAddr) {
        String clientMac = clientEthAddr.toLowerCase();

        log.info("Client message from " + agentAddr.getHostAddress() + ": " +
               clientMac + " - " + clientIpAddr);

        if (!isAPAgentTracked(agentAddr)) {
            log.warn("Found unrecorded agent ap");
            addUnrecordedAPAgent(agentAddr);
        }

        //FIXME this is a bug for current dhcp module
        // if client's mac is in allClientMap but agent is not the same
        // we will first compare current time with client.connectTime
        // 1) if they are very close, emit the later client message
        // 2) else use the second to replace the older one
        if (allClientMap.containsKey(clientMac)) {
            Client clt = allClientMap.get(clientMac);

            long currTime = System.currentTimeMillis();
            if (currTime - clt.getConnectTime() <= 1000) {
                log.info("Client message from " + agentAddr.getHostAddress()
                        + ": redundant dhcp request, ignore it...");
                return;
            }

            APAgent agent = clt.getAgent();
            if (!(agent.getIpAddress().getHostAddress().equals(agentAddr.getHostAddress()))) {
                // client has connected to a new AP, inform old agent
                byte[] message = makeByteMessageToAgent("a", "rm" + clientMac);
                agent.send(message);
                agent.removeClient(clientMac);
                allClientMap.remove(clientMac);
            }
        }
        
        // ask APAgent to handle the info
        APAgent agent = apAgentMap.get(agentAddr.getHostAddress());
        Client client = agent.receiveClientInfo(MacAddress.of(clientMac), IPv4Address.of(clientIpAddr));

        // record the initialised client object returned from APAgent
        if (!allClientMap.containsKey(clientMac) && client != null) {
            allClientMap.put(clientMac, client);
        }
    }

    /**
     * Handle ClientDisconnect message from an agent.
     *
     * @param AgentAddr
     */
    synchronized void clientDisconnect(final InetAddress agentAddr,
            final String clientEthAddr) {

        if (!isAPAgentTracked(agentAddr)) {
            log.warn("Found unrecorded agent ap, ignore it!");
            return;
        }

        Client clt = allClientMap.get(clientEthAddr);
        if (clt.getAgent().getIpAddress().equals(agentAddr)) {
            // APAgent delete client map
            apAgentMap.get(agentAddr.getHostAddress()).removeClient(clientEthAddr);

            // Master delete client map
            allClientMap.remove(clientEthAddr.toLowerCase());
            log.info("Client " + clientEthAddr + " disconnected from agent "
                    + agentAddr.getHostAddress());
        } else {
            log.info("Agent " + agentAddr.getHostAddress() 
                    + ": ignore client disconnect message");
        }
    }

    /**
     * Handle a agent rate message from an agent.
     * This function will not be used anymore!!! click agent will not send
     * rate message!
     *
     * @param AgentAddr
     */
    void receiveAgentRate(final InetAddress agentAddr, final String upRate, final String downRate) {
        log.debug("Agent rate message from " + agentAddr.getHostAddress() +
                 ": " + upRate + " " + downRate);

        if (!isAPAgentTracked(agentAddr)) {
            log.warn("Found unrecorded agent ap");
            addUnrecordedAPAgent(agentAddr);
        }

        double r1 = Double.parseDouble(upRate);
        double r2 = Double.parseDouble(downRate);
        apAgentMap.get(agentAddr.getHostAddress()).updateUpRate(r1);
        apAgentMap.get(agentAddr.getHostAddress()).updateDownRate(r2);
        // System.out.println(apAgentMap.get(agentAddr.getHostAddress()).toString());
    }

    /**
     * Handle a client rate message from an agent.
     * This method will not be used anymore!!! click agent will not send rate
     * statistics to the master. The corresponding statistics task has been migrated to 
     * OFClientRateStatistics module based on openflow sw.
     *
     * @param AgentAddr
     */    
    void receiveClientRate(final InetAddress agentAddr, final String clientEthAddr,
            final String clientIpAddr, final String upRate, final String downRate) {

        log.debug("Client rate message from " + agentAddr.getHostAddress() +
                ": " + clientEthAddr + " -- " + clientIpAddr + " -- " +
                upRate + " " + downRate);

        if (!isAPAgentTracked(agentAddr)) {
            log.warn("Found unrecorded agent ap");
            addUnrecordedAPAgent(agentAddr);
        }

        double r1 = Double.parseDouble(upRate);
        double r2 = Double.parseDouble(downRate);
        Client clt = apAgentMap.get(agentAddr.getHostAddress()).receiveClientRate(MacAddress.of(clientEthAddr), r1, r2);
        
        if (clt != null) { // update client info in the master
            allClientMap.put(clientEthAddr.toLowerCase(), clt);
        }
    }

    synchronized void receiveTimestamp() {
        log.debug("Received start timestamp for client downloading!");
        startTime = System.currentTimeMillis();
    }
    //not in use in OFMonitor
/*
    void switchQueueManagement(IOFSwitch sw, SwitchOutQueue swQueue) {

        List<OFStatistics> values = null;
        Future<List<OFStatistics>> future;
        OFFlowStatisticsReply reply;

        try {
            OFStatisticsRequest req = new OFStatisticsRequest();
            req.setStatisticType(OFStatisticsType.FLOW);
            int requestLength = req.getLengthU();
            OFFlowStatisticsRequest specificReq = new OFFlowStatisticsRequest();
            OFMatch mPattern = new OFMatch();
            mPattern.setWildcards(Wildcards.FULL.matchOn(Flag.IN_PORT));
            mPattern.setInputPort((short)swQueue.getOutPort());
            specificReq.setMatch(mPattern);
            specificReq.setTableId((byte)0xff);

            // using OFPort.OFPP_NONE(0xffff) as the outport
            specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
            req.setStatistics(Collections.singletonList((OFStatistics) specificReq));
            requestLength += specificReq.getLength();
            req.setLengthU(requestLength);

            // make the query
            future = sw.queryStatistics(req);
            values = future.get(2, TimeUnit.SECONDS);

            if (values != null) {
                OFMatch match = null;
                Map<Double, OFMatch> rateMap = new HashMap<Double, OFMatch>();
                List<Double> rateList = new ArrayList<Double>();

                for (OFStatistics stat: values) {
                    // statsReply.add((OFFlowStatisticsReply) stat);

                    reply = (OFFlowStatisticsReply) stat;
                    double rate = reply.getByteCount()
                                  / ((double) reply.getDurationSeconds()
                                  + ((double) reply.getDurationNanoseconds() / 1000000000));
                    if (!reply.getActions().isEmpty() && rate > 0) {
                        match = reply.getMatch();
                        if (rateMap.containsKey(rate)) {
                            rate = rate + 0.1;
                            // FIXME current rate is not a good choice for hash key
                            // for avoiding the same rate, here I will change the
                            // actual rate value by adding 0.1
                        }
                        rateMap.put(rate, match);
                        rateList.add(rate);
                    }
                }

                java.util.Collections.sort(rateList);
                java.util.Collections.reverse(rateList);


                // System.out.println("rateList: " + rateList);

                offloadingCandidates.clear();
                int size = rateList.size();
                if (size > 3) {
                    size = 3;
                }
                for (int i = 0; i < size; i++) {
                    double rate = rateList.get(i);
                    match = rateMap.get(rate);
                    if (match != null) {
                        MACAddress macAddr = new MACAddress(match.getDataLayerDestination());
                        String mac = macAddr.toString().toLowerCase();
                        if (allClientMap.containsKey(mac)) {
                            Client client = allClientMap.get(mac);
                            offloadingCandidates.add(client);
                            APAgent agent = client.getAgent();
                            if (agent != null) {
                                // set up message data
                                byte[] message = makeByteMessageToClient(macAddr, "c", "app");
                                agent.send(message);
                                log.info("Send message to agent for collecting client app info");
                            }
                        }
                    }
                }


            }
        } catch (Exception e) {
            log.error("Failure retrieving flow statistics from switch " + sw, e);
        }
    }
*/    
    void agentTrafficManagement(IOFSwitch sw, APAgent agent) {
        
    	if (agent.getClientNum() > 1) {
    		log.info("Agent " + agent.getSSID() + " reach port download threshold!!!");
    		
    		Future<List<OFStatsReply>> future;
        	List<OFStatsReply> values;
        	
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
					Map<Client, Double> rateMap = new HashMap<Client, Double>();
					for (OFStatsReply r : values) {
		                OFFlowStatsReply psr = (OFFlowStatsReply) r;
		                for (OFFlowStatsEntry pse : psr.getEntries()) {
		                	double rate = pse.getByteCount().getValue()
		                			/((double) pse.getDurationSec()
		                		    +((double) pse.getDurationNsec() / 1000000000));
		                	log.info("Test1.2agentTrafficManagement rate:"+rate);
		                	if (!ActionUtils.getActions(pse).isEmpty() && rate > 0) {
		                		Match match = pse.getMatch();
		                		
		                		 for (Client clt: agent.getAllClients()){
		                			 if (clt.getMacAddress().equals(match.get(MatchField.ETH_DST))) {
		                                    if (rateMap.containsKey(clt)) {
		                                        // FIXME this accumulation may result a wrong rate sum!!!
		                                    	log.info("Test1.2agentTrafficManagement cltinfo:"+clt.toString());
		                                        rateMap.put(clt, rateMap.get(clt) + rate);
		                                    } else {
		                                        rateMap.put(clt, rate);
		                                    }
		                                    break;
		                                } 
		                		 }		                		
		                	}		                							                	
		                }
					}
					// find offloading candidate
                    Client cltWithMaxRate = null;
                    double maxRate = 0;
                    for (Client clt: rateMap.keySet()) {
                        double rate = rateMap.get(clt);
                        if (maxRate < rate) {
                            maxRate = rate;
                            cltWithMaxRate = clt;
                        }
                    }
                    
                 // send management data
                    if (cltWithMaxRate != null && !cltWithMaxRate.isBeningEvaluated()) {
                        byte[] message = makeByteMessageToClient(cltWithMaxRate.getMacAddress(), "c", "motion");
                        agent.send(message);
                        
                        message = makeByteMessageToClient(cltWithMaxRate.getMacAddress(), "c", "app");
                        agent.send(message);
                        cltWithMaxRate.startOffloadingEvaluation();
                        log.info("Send message to agent " + agent.getSSID() 
                                + " for collecting client motion and app info");
                    }
                    
                    
					
				}
		    } catch (Exception e) {
                log.error("Failure retrieving flow statistics from switch " + sw, e);
            }
    	}else {
    		return;
    	}
       
    }

    private byte[] makeByteMessageToClient(MacAddress mac, String signal, String data) {
        byte[] m = mac.getBytes();
        byte[] b1 = signal.getBytes();
        byte[] b2 = (data + "|\n").getBytes();

        byte[] message = new byte[b1.length + b2.length + m.length];

        System.arraycopy(b1, 0, message, 0, b1.length);
        System.arraycopy(m, 0, message, b1.length, m.length);
        System.arraycopy(b2, 0, message, b1.length + m.length, b2.length);

        return message;
    }

    private byte[] makeByteMessageToAgent(String signal, String data) {
        byte[] b1 = signal.getBytes();
        byte[] b2 = (data + "|\n").getBytes();

        byte[] message = new byte[b1.length + b2.length];

        System.arraycopy(b1, 0, message, 0, b1.length);
        System.arraycopy(b2, 0, message, b1.length, b2.length);

        return message;
    }

    void receiveCltAppInfo(String cltEthAddr, String app) {
        log.debug("Received app info from " + cltEthAddr + " - " + app);
        MacAddress macAddr = MacAddress.of(cltEthAddr);
        Client clt = allClientMap.get(cltEthAddr);

//        if (app.toLowerCase().equals("youtube") && clt != null) {
//            clt.setApp("youtube");
//            byte[] msg = makeByteMessageToClient(macAddr, "c", "scan|\n");
//            clt.getAgent().send(msg);
//            log.info("ask client (" + cltEthAddr + ") to scan");
//            return;
//        }

        log.info("Send message to agent " + clt.getAgent().getSSID() 
                + " for collecting wifi signal level");
        byte[] msg = makeByteMessageToClient(macAddr, "c", "scan|\n");
        clt.getAgent().send(msg);
    }


    // TODO now elements in apAgentMap are indexed with agent IP address,
    // which makes the search more complicated here (two-level for loop)
    // One solution might be adding another AP map which uses BSSIDs as Hash
    // keys
    void receiveScanResult(String[] fields) {

        log.info("Received scan result from " + fields[1]);
        MacAddress macAddr = MacAddress.of(fields[1]);
        Client clt = allClientMap.get(macAddr.toString().toLowerCase());
        if (clt == null) {
            log.warn("Request from unknown client " + fields[1] + ", discard it...");
            return;
        }
        
        clt.updateSignalInfo(Arrays.copyOfRange(fields, 3, fields.length - 1));
        if (fields[2].toLowerCase().equals("static")) {
            clt.updateStaticFlag(true);
        }
        
        if (clt.isReadyToOffload()) {
            log.info("Preparing offloading...");
            Map<String, Double> apBandwidthUtilizationMap = new HashMap<String, Double>();
            Map<String, Double> cltPotentialRateMap = new HashMap<String, Double>();

            //System.out.println("*****************");
            //System.out.println(apAgentMap.toString());
            //System.out.println("******************");
            
            // get max rate value
            Set<String> apSet = clt.getNearbyAPSet();
            
            //System.out.println("+++++++++++++ " + apSet.toString());
            
            double maxPotentialRate = 0;
            for (String bssid: apSet) {
                for (APAgent agent: apAgentMap.values()) {
                    if (agent.getBSSID().toLowerCase().equals(bssid)) {
                        
                        //System.out.println("---------" + bssid);


                        double rate, restRate, otherCltRate, agentRate;
                        if (clt.getAgent().getBSSID().toLowerCase().equals(bssid)) {
                            rate = clt.getDownRate() / 1000000;
                            // agentRate = agent.getDownRate() / 1000000;
                            double agentDownBW = agent.getDownlinkBW();
                            // if (agentRate > agentDownBW) {
                            //     agentRate = agentDownBW;
                            // }
                            
                            otherCltRate = 0;
                            for (Client c : agent.getAllClients()) {
                            	if (!c.equals(clt)) {
                            		// System.out.println(c.getDownRate());
                            		otherCltRate += c.getDownRate() / 1000000;
                            	}
                            }
                            
                            // System.out.println("*****otherCltRate: " + otherCltRate);

                            restRate = agentDownBW - otherCltRate;
                            if (restRate < 0) {
                            	restRate = 0;
                            }
                            
                            log.info("rate values of current ap: rate=" + rate + ", restRate=" + restRate);
                        } else { // estimated bandwidth for client
                            agentRate = agent.getDownRate() / 1000000;
                            restRate = agent.getDownlinkBW() - agentRate;
                            if (restRate < 0) {
                            	restRate = 0;
                            }
                            log.info("rate values of different ap: rate=" + agentRate + ", restRate=" + restRate);
                        }
                        
                        cltPotentialRateMap.put(bssid, restRate);
                        apBandwidthUtilizationMap.put(bssid, restRate / agent.getDownlinkBW());
                        if (restRate > maxPotentialRate) {
                            maxPotentialRate = restRate;
                        }

                        break;
                    }
                }
            }
        
            
            // log.info("maxPotentialRate=" + maxPotentialRate);
           
            //System.out.println("-------------- " + cltPotentialRateMap.toString());
            //System.out.println("-------------- " + apBandwidthUtilizationMap.toString());

            // evaluate each AP
            String candidateBSSID = null;
            double metric = 0;
            boolean firstAPCandidate = true;
            for (String bssid: apBandwidthUtilizationMap.keySet()) {
                try {
                    double signalMetric = clt.signalEvaluation(bssid);
                    double overheadMetric;
                    if (clt.getAgent().getBSSID().toLowerCase().equals(bssid)) {
                        overheadMetric = 0;
                    } else {
                        overheadMetric = 0.2;
                    }
                    double rate = cltPotentialRateMap.get(bssid);
                    double restRateUtilization = apBandwidthUtilizationMap.get(bssid);
                    double evaluationMetric = signalMetric * rate / maxPotentialRate 
                                                    * restRateUtilization
                                                    - overheadMetric;
                    
                    log.info("metric for AP " + bssid + ": " + signalMetric + " * " 
                                + rate + " / " + maxPotentialRate + " * " + restRateUtilization
                                + " - " + overheadMetric + " = " + evaluationMetric);
                    
                    if (firstAPCandidate) {
                        candidateBSSID = bssid;
                        metric = evaluationMetric;
                        firstAPCandidate = false;
                    } else if (evaluationMetric > metric) {
                        candidateBSSID = bssid;
                        metric = evaluationMetric;
                    }
                    
                } catch (Exception e) {
                    log.error("Failure to evaluate AP " + bssid, e);
                }
            }

            log.info("final candidate: " + candidateBSSID + ", metric: " + metric);
            
            if (candidateBSSID != null) {
                if (candidateBSSID.equals(clt.getAgent().getBSSID())) {
                    log.info("No other AP is better for offloading!");
                } else {
                    boolean isOffloadingPerformed = false;
                    for (APAgent agent: apAgentMap.values()) {
                        if (agent.getBSSID().toLowerCase().equals(candidateBSSID)) {
                            // System.out.println(agent.toString());
                            IOFSwitch sw = clt.getSwitch();
                            log.info("Test1.2receiveScanResult:trigger findOFFlowEntryByDstMacAddr" );
                            List<Match> matchList = findOFFlowEntryByDstMacAddr(sw, clt.getMacAddress());
                            
                            byte[] msg = makeByteMessageToClient(macAddr, "c", "switch|"
                                                    + agent.getSSID() + "|"
                                                    + agent.getBSSID() + "|"
                                                    + agent.getAuth());
                            clt.getAgent().send(msg);
                            
                            // change old OF flow entries
                            // this may not needed if candidate is connected to a different OFswitch
                            log.info("Test1.2receiveScanResult:trigger changeOFFlowOutport" );
                            changeOFFlowOutport(matchList, sw, OFPort.of(agent.getOFPort()));
                            
                            log.info("Ask client (" + fields[1] + ") to switch to " + agent.getSSID());

                            isOffloadingPerformed = true;
                            break;
                        }
                    }
                    
                    if (!isOffloadingPerformed) {
                        log.error("Can not find this agent for offloading: " + candidateBSSID);
                    }
                }
                
            } else if (enableCellular == true) {
                byte[] msg = makeByteMessageToClient(macAddr, "c", "wifioff|");
                clt.getAgent().send(msg);
                log.info("Ask client to use cellular network");
            }
            
            clt.finishOffloadingEvaluation();
        }
    }
    
    
    void changeOFFlowOutport(List<Match> matchList, IOFSwitch sw, OFPort outPort) {
    	OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowModifyStrict();
    	fmb.setHardTimeout((short) 0)
        .setIdleTimeout((short) 20)
        .setBufferId(OFBufferId.NO_BUFFER);
		
		for (Match match: matchList) {
			fmb.setMatch(match);
	        fmb.setOutPort(outPort);
	        
	        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			OFActionOutput.Builder action = sw.getOFFactory().actions().buildOutput();
	            
	        action.setMaxLen(0xffff);
		    action.setPort(outPort);
		    actionList.add(action.build());
				
	        fmb.setActions(actionList);
	            	            
	        try {
	        	OFFlowMod fm = fmb.build();
	            sw.write(fm, LogicalOFMessageCategory.MAIN);
	            log.info("Test1.2changeOFFlowOutport success write to switch the flowmod is"+fm.toString());
	        } catch (Exception e) {
	            log.error("Failure to modify flow entries", e);
	        }			 
		 }
        
    }
    
    
    List<Match> findOFFlowEntryByDstMacAddr(IOFSwitch sw, MacAddress mac) {

        List<Match> matchList = new ArrayList<Match>();
        Future<List<OFStatsReply>> future;
    	List<OFStatsReply> values;
    	
    	Match.Builder matchBuilder = sw.getOFFactory().buildMatch();
    	matchBuilder.setExact(MatchField.ETH_DST, mac);
    	
    	OFStatsRequest req = sw.getOFFactory().buildFlowStatsRequest()
                .setMatch(matchBuilder.build())
                .setTableId(TableId.ALL)
                .setOutPort(OFPort.NO_MASK)
                .build();
    	
    	   		
	    try {
	    	
	    	future =  sw.writeStatsRequest(req); 
			values = future.get(2, TimeUnit.SECONDS);
			
			if (values != null) {
				
				for (OFStatsReply r : values) {
	                OFFlowStatsReply psr = (OFFlowStatsReply) r;
	                for (OFFlowStatsEntry pse : psr.getEntries()) {
	                	matchList.add(pse.getMatch());
	                	log.info("Test1.2findOFFlowEntryByDstMacAddr the match is:"+pse.getMatch().toString());
	                }
				}
			}
	    } catch (Exception e) {
            log.error("Fail to retriev flow entry from switch " + sw.toString(), e);
        }
        
        
        return matchList;
    }

            



    //********* from IFloodlightModule **********//

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
    	Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(ISoftOffloadService.class);
        return l;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        Map<Class<? extends IFloodlightService>, IFloodlightService> m =
        		new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        // m.put(Master.class, this);
        m.put(ISoftOffloadService.class, this);
        return m;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
            new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IRestApiService.class);
        l.add(IOFSwitchService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        restApi = context.getServiceImpl(IRestApiService.class);
        IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
        executor = tp.getScheduledExecutor();
    }

    @Override
    public void startUp(FloodlightModuleContext context)
            throws FloodlightModuleException {

    	switchService.addOFSwitchListener(this);
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

        // read configure options
        Map<String, String> configOptions = context.getConfigParams(this);
        
        // cellular offloading
        String flag = configOptions.get("enableCellular");
        if (flag.toLowerCase().equals("true")) {
            this.enableCellular = true;
        }

        // master port config
        int port = DEFAULT_PORT;
        String portNum = configOptions.get("masterPort");
        if (portNum != null) {
            port = Integer.parseInt(portNum);
        }

        int monitorNum = OF_MONITOR_MAX_NUM;
        String num = configOptions.get("ofMonitorMaxNum");
        if (num != null) {
            monitorNum = Integer.parseInt(num);
        }

        double monitorInterval = OF_MONITOR_INTERVAL;
        String interval = configOptions.get("ofMonitorInterval");
        if (interval != null) {
            monitorInterval = Double.parseDouble(interval);
        }

        // network topology config
        String networkTopoFile = DEFAULT_TOPOLOGY_FILE;
        String networkTopoFileConfig = configOptions.get("networkFile");
        if (networkTopoFileConfig != null) {
            networkTopoFile = networkTopoFileConfig;
        }
        parseNetworkConfig(networkTopoFile);

        // ap config
        String apConfigPath = DEFAULT_AP_CONFIG;
        String apConfig = configOptions.get("apConfig");
        if (apConfig != null) {
            apConfigPath = apConfig;
        }
        parseAPConfig(apConfigPath);


        IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
        executor = tp.getScheduledExecutor();
        // Spawn threads for different services
        executor.execute(new ClickManageServer(this, port, executor));

        // Statistics
        executor.execute(new OFMonitor(this.floodlightProvider,this.switchService, this, monitorInterval, monitorNum, swQueueList));
        executor.execute(new OFRateStatistics(this.floodlightProvider, this, monitorInterval));
        restApi.addRestletRoutable(new SoftOffloadWebRoutable());
    }

    private void parseNetworkConfig(String networkTopoFile) {
        log.info("parsing network config...");
        try {

            BufferedReader br = new BufferedReader (new FileReader(networkTopoFile));
            String strLine;

            // TODO now the config parser is quite simple, and can only handle
            // the format which strictly follows our definition without any
            // error

            /* Each line has the following format:
             *
             * Key value1 value2...
             */
            while ((strLine = br.readLine()) != null) {
                if (strLine.startsWith("#")) // comment
                    continue;

                if (strLine.length() == 0) // blank line
                    continue;

                // Openflow Switch IP Address
                String [] fields = strLine.split(" ");
                if (!fields[0].equals("OFSwitchIP")) {
                    log.error("Missing OFSwitchIP field " + fields[0]);
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length != 2) {
                    log.error("A OFSwitch field should specify a single string as IP address");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                String swIP = fields[1];

                // outport
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after OFSwitchIP field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("OutPort")){
                    log.error("A OFSwitchIP field should be followed by a OUTPORT field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No port value is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                int outport = Integer.parseInt(fields[1]);


                // Ingress BandWidth
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after OFSwitchIP field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("BandWidth")){
                    log.error("A OutPort field should be followed by a BandWidth field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No bandwidth value is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                int bandwidth = Integer.parseInt(fields[1]);

                // APs
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after OFSwitchIP field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("AP")){
                    log.error("A OUTPORT field should be followed by a AP field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("An AP field must have at least one ap defined for it");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }

                ArrayList<String> apList = new ArrayList<String>();
                for (int i = 1; i < fields.length; i++) {
                    apList.add(fields[i]);
                }

                SwitchNetworkConfig swconfig = new SwitchNetworkConfig(swIP, outport, bandwidth, apList);

                if (networkTopoConfig.contains(swconfig)) {
                    log.error("Found dupliated switch network");
                    System.exit(1);
                }

                networkTopoConfig.add(swconfig);
            }

            br.close();

        } catch (FileNotFoundException e) {
            log.error("Network topology config is not found, terminating: " + e);
            System.exit(1);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void parseAPConfig (String apConfigPath) {
        log.info("parsing AP config...");
        
        try {
            BufferedReader br = new BufferedReader (new FileReader(apConfigPath));
            String strLine;

            while ((strLine = br.readLine()) != null) {
                if (strLine.startsWith("#")) // comment
                    continue;

                if (strLine.length() == 0) // blank line
                    continue;

                // Managed IP Address
                String [] fields = strLine.split(" ");
                if (!fields[0].equals("ManagedIP")) {
                    log.error("Missing ManagedIP field " + fields[0]);
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length != 2) {
                    log.error("A ManagedIP field should specify a single string as IP address");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                String ip = fields[1];

                // SSID
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after ManagedIP field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ", 2);
                if (!fields[0].equals("SSID")){
                    log.error("A ManagedIP field should be followed by a SSID field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No SSID is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                String ssid = fields[1];

                // BSSID
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after OFSwitchIP field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("BSSID")){
                    log.error("A SSID field should be followed by a BSSID field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No BSSID is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                String bssid = fields[1];

                // AUTH
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after BSSID field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("AUTH")){
                    log.error("A BSSID field should be followed by a AUTH field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No AUTH value is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                String auth = fields[1];
                
                // OFPort
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after AUTH field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("OFPort")){
                    log.error("A AUTH field should be followed by a OFPort field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No OFPort is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                short ofport = Short.parseShort(fields[1]);
                
                // Bandwidth
                strLine = br.readLine();
                if (strLine == null) {
                    log.error("Unexpected EOF after OFPort field: ");
                    System.exit(1);
                }
                fields = strLine.split(" ");
                if (!fields[0].equals("DownlinkBW")){
                    log.error("A OFPort field should be followed by a DownlinkBW field");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                if (fields.length == 1) {
                    log.error("No Bandwidth is given!");
                    log.error("Offending line: " + strLine);
                    System.exit(1);
                }
                double bw = Double.parseDouble(fields[1]);

                apConfigMap.put(ip, new APConfig(ip, ssid, bssid, auth, ofport, bw));
            }

            br.close();

        } catch (FileNotFoundException e) {
            log.error("AP config is not found, terminating: " + e);
            System.exit(1);
        } catch (IOException e) {
            log.error("Failed to read AP config, terminating: " + e);
            e.printStackTrace();
            System.exit(1);
        }
    }



    /** IOFSwitchListener and IOFMessageListener methods **/

    @Override
    public String getName() {
        return "SoftOffload-Master";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public net.floodlightcontroller.core.IListener.Command receive(
            IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        OFPacketIn pi = (OFPacketIn) msg;
        
        OFPort inPort =(pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        
        Match match = createMatchFromPacket(sw,inPort,cntx);
        
        MacAddress srcMacAddr = match.get(MatchField.ETH_SRC);
        
        for (APAgent agent: apAgentMap.values()) {
            Client clt = agent.getClient(srcMacAddr.toString());

            if (clt != null) {
                if (clt.getSwitch() == null) {
                    clt.setSwitch(sw);
                } else if (clt.getSwitch().getId() != sw.getId()) {
                    log.warn("Client dpid might be different from associated AP!");
                    clt.setSwitch(sw);
                }
            }
        }

        return null;
    }
    protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort)
		.setExact(MatchField.ETH_SRC, srcMac)
		.setExact(MatchField.ETH_DST, dstMac);


		return mb.build();
	}

    @Override
    public void switchAdded(DatapathId switchId) {
        // TODO Auto-generated method stub

    }

    @Override
    public void switchRemoved(DatapathId switchId) {
        List<SwitchOutQueue> tempList = new LinkedList<SwitchOutQueue>();

        // remove corresponding agent
        for (String key: apAgentMap.keySet()) {
        	if (apAgentMap.get(key).getSwitch().getId().equals(switchId)) {
        		apAgentMap.remove(key);
        	}
        }
        
        // remove sw from swQueseList
        for (SwitchOutQueue swqueue: swQueueList) {
            if (swqueue.getSwId().equals(switchId)) {
                tempList.add(swqueue);
            }
        }

        for (SwitchOutQueue sw: tempList) {
            swQueueList.remove(sw);
        }
    }

    @Override
    public void switchActivated(DatapathId switchId) {
        IOFSwitch sw = switchService.getActiveSwitch(switchId);

        InetSocketAddress swInetAddr = (InetSocketAddress) sw.getInetAddress();
        String swInetAddrStr = swInetAddr.getAddress().getHostAddress();

        boolean hasSwitchInConfig = false;
        for (SwitchNetworkConfig sc: networkTopoConfig) {
            if (sc.swIPAddr.toLowerCase().equals(swInetAddrStr.toLowerCase())) {
                hasSwitchInConfig = true;

                List<APAgent> agentList = new LinkedList<APAgent>();
                for (String agentInetAddr: sc.apList) {
                    if (apConfigMap.containsKey(agentInetAddr)) {
                        APConfig apConfig = apConfigMap.get(agentInetAddr);
                        APAgent agent = new APAgent(agentInetAddr, sw, 
                                                    apConfig.ssid, apConfig.bssid, 
                                                    apConfig.auth, apConfig.ofPort, apConfig.downlinkBW);
                        
                        apAgentMap.put(agentInetAddr, agent);
                        agentList.add(agent);
                        log.info("Initialize AP " + apConfig.ssid + " (" + apConfig.bssid + ")");
                        agent.checkClients();
                    } else {
                        log.warn("Unconfiged AP found with siwtch " + swInetAddrStr);
                        log.warn("Initialize AP " + agentInetAddr + " without SSID and BSSID");
                        APAgent agent = new APAgent(agentInetAddr, sw, "", "", "open", (short)0, 0);
                        apAgentMap.put(agentInetAddr, agent);
                        agentList.add(agent);
                    }
                }

                swQueueList.add(new SwitchOutQueue(switchId, sc.outPort, sc.bandwidth, agentList));
            }
        }

        if (!hasSwitchInConfig) {
            log.warn("Unrecording switch is connected and activated, ignore it!");
        }
    }
    
    @Override
	public void rowsModified(String tableName, Set<Object> rowKeys) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void rowsDeleted(String tableName, Set<Object> rowKeys) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
   
	@Override
	public void switchDeactivated(DatapathId switchId){
		// TODO Auto-generated method stub
		
	}
    
    
    //********* REST API **********//
    
    @Override
    public Collection<APAgent> getAgents() {
        return apAgentMap.values();
    }

    @Override
    public APAgent getAgent(String agentIp) {
        return apAgentMap.get(agentIp);
    }

    @Override
    public Client getClient(String clientMac) {
        return allClientMap.get(clientMac.toLowerCase());
    }


}
