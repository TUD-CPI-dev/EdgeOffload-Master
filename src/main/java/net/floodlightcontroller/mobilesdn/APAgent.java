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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.mobilesdn.web.AgentJsonSerializer;
import net.floodlightcontroller.core.IOFSwitch;

/**
 * APAgent class is designed for recording and manage AP(local agent) info:
 * 1) ap's rate and ip address info
 * 2) connecting client mapping
 *
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
@JsonSerialize(using=AgentJsonSerializer.class)
public class APAgent implements Comparable<Object> {
    protected static Logger log = LoggerFactory.getLogger(APAgent.class);

    private InetAddress ipAddress;
    private String ssid;
    private String bssid;
    private String auth;
    private short ofPort;
    private double downlinkBW;

    private double upRate;      // up rate of agent eth port
    private double downRate;	// down rate of agent eht port
    private Map<MacAddress, Client> clientMap = new ConcurrentHashMap<MacAddress, Client>();
    private IOFSwitch ofSwitch = null;          // not initialized
    private DatagramSocket agentSocket = null;
    // private boolean offloadingFlag = false;   // OFMonitor may change this to true
    
    // used for new OFMonitor statistics
    private long ofDownBytes = 0;
    private long ofUpBytes = 0;
    private double ofDownRate;
    private int downRateOverNum = 0;
    private int pendingNum = 0;


    // defaults
    private final int AGENT_PORT = 6777;
    static private final float RATE_THRESHOLD = 500000;
    static private final int MAX_LEN = 512;


    public APAgent(InetAddress ipAddr) {
        this.ipAddress = ipAddr;

        try {
            this.agentSocket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public APAgent(String ipAddr) {

        try {
            this.ipAddress = InetAddress.getByName(ipAddr);
            this.agentSocket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (UnknownHostException e1) {
			
			e1.printStackTrace();
			 System.exit(1);
		}
    }

    public APAgent(InetAddress ipAddr, IOFSwitch sw, String s, String b, String auth, short port, double bw) {
        this.ipAddress = ipAddr;
        this.ofSwitch = sw;
        this.ssid = s;
        this.bssid = b;
        this.auth = auth;
        this.ofPort = port;
        this.downlinkBW = bw;

        try {
            this.agentSocket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public APAgent(String ipAddr, IOFSwitch sw, String s, String b, String auth, short port, double bw) {

        this.ofSwitch = sw;
        this.ssid = s;
        this.bssid = b;
        this.auth = auth;
        this.ofPort = port;
        this.downlinkBW = bw;

        try {
            this.ipAddress = InetAddress.getByName(ipAddr);
            this.agentSocket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (UnknownHostException e1) {
        	e1.printStackTrace();
            System.exit(1);
		}
    }

    /**
     * Get the AP's management IPv4 address.
     * @return
     */
    public InetAddress getIpAddress() {
        return this.ipAddress;
    }

    /**
     * get AP's total up rate value
     * @return
     */
    public synchronized double getUpRate() {
        return this.upRate;
    }

    /**
     * Set the AP's up rate value
     * @param r
     */
    public synchronized void updateUpRate(double r) {
        this.upRate = r;
    }

    /**
     * get AP's total down rate value
     * @return downRate (float)
     */
    public synchronized double getDownRate() {
        return this.downRate;
    }

    /**
     * Set the AP's down rate value
     * @param r
     */
    public synchronized void updateDownRate(double r) {
        this.downRate = r;
    }

    /**
     * get AP's corresponding openflow switch instance
     * @return
     */
    public IOFSwitch getSwitch() {
        return this.ofSwitch;
    }
    
    /**
     * get AP's max downlink bandwidth
     * @return
     */
    public double getDownlinkBW() {
        return this.downlinkBW;
    }

    /**
     * set AP's associating openflow switch instance
     * @return
     */
    public void setSwitch(IOFSwitch sw) {
        this.ofSwitch = sw;
    }

    public String getSSID() {
        return this.ssid;
    }

    public String getBSSID() {
        return this.bssid;
    }

    public String getAuth() {
        return this.auth;
    }

    public void setSSID(String s) {
        ssid = s;
    }

    public void setBSSID(String b) {
        bssid = b;
    }

    public void setAuth(String auth) {
        this.auth = auth;
    }
    
    public short getOFPort() {
        return this.ofPort;
    }

    public void setOFPort(short port) {
        ofPort = port;
    }
    
    public void setDownlinkBW(double bw) {
        downlinkBW = bw;
    }
    
    
    // these following funcs might be removed later
    public int getDownRateOverNum() {
        return downRateOverNum;
    }

    public int getPendingNum() {
        return pendingNum;
    }
    
    public long getOFDownBytes() {
        return ofDownBytes;
    }

    public long getOFUpBytes() {
        return ofUpBytes;
    }

    public void setOFDownBytes(long bytes) {
        ofDownBytes = bytes;
    }

    public void setOFUpBytes(long bytes) {
        ofUpBytes = bytes;
    }

    public void setDownRateOverNum(int num) {
        downRateOverNum = num;
    }

    public void setPendingNum(int num) {
        pendingNum = num;
    }
    
    public double getOFDownRate() {
        return ofDownRate;
    }

    public void setOFDownRate(double rate) {
        ofDownRate = rate;
    }
    


    /**
     * Add a client to the agent tracker
     *
     * @param hwAddress Client's hw address
     * @param ipv4Address Client's IPv4 address
     */
    // public void addClient(final MACAddress clientHwAddress, final InetAddress ipv4Address) {
        // // we use lower case keys for the clientMap
        // String mac = clientHwAddress.toString().toLowerCase();

        // if (ofSwitch != null) {
            // clientMap.put(mac, new Client(clientHwAddress, ipv4Address, ofSwitch, this));
        // } else {
            // clientMap.put(mac, new Client(clientHwAddress, ipv4Address, this));
        // }
    // }

    /**
     * Add a client to the agent tracker
     *
     * @param initailized client instance
     */
    public void addClient(Client client) {
       
        clientMap.put(client.getMacAddress(), client);
    }

    /**
     * get the corresponding client instance
     *
     * @param macAddress MAC address string
     */
    public Client getClient(String clientMacStr) {
        // assert clientMap.containsKey(macAddress);

        return clientMap.get(MacAddress.of(clientMacStr));
    }

    /**
     * get the corresponding client instance
     *
     * @param macAddress MAC address
     */
    public Client getClient(MacAddress clientMac) {

        return clientMap.get(clientMac);
    }

    /**
     * get all corresponding client instances
     *
     */
    public Collection<Client> getAllClients() {

        return clientMap.values();
    }

    /**
     * Remove a client from the agent tracker
     *
     * @param client - initailized client instance
     */
    public void removeClient(Client client) {
        MacAddress clientMac = client.getMacAddress();

        if (clientMap.containsKey(clientMac)) {
            // clientMap.get(clientMac).cancelTask();
            clientMap.remove(clientMac);
        }
    }

    /**
     * Remove a client from the agent tracker
     *
     * @param mac address string
     */
    public void removeClient(String clientMac) {
        MacAddress mac = MacAddress.of(clientMac);

        if (clientMap.containsKey(mac)) {
            // clientMap.get(mac).cancelTask();
            clientMap.remove(mac);
        }
    }

    /**
     * Remove all clients from the agent tracker
     *
     */
    public void removeAllClients() {
        // for (Client i: clientMap.values()) {
        //     i.cancelTask();
        // }

        clientMap.clear();
    }

    /**
     * get client number on this agent
     *
     * @param macAddress MAC address
     */
    public int getClientNum() {
        return clientMap.size();
    }
    
    /**
     * set offloadingFlag, this flag is used to indicate whether offloading is 
     * needed now for this AP
     *
     * @param macAddress MAC address
     */
    /**
    public synchronized void setOffloadingFlag(boolean flag) {
        offloadingFlag = flag;
    }
    
    public boolean getOffloadingFlag() {
        return offloadingFlag;
    }
    */

    public void send(String message) {
        // send message to agent ap
        byte[] buf = new byte[MAX_LEN];
        buf = message.getBytes();
        DatagramPacket packet = new DatagramPacket(buf, buf.length,
                                        this.ipAddress, this.AGENT_PORT);
        try {
            this.agentSocket.send(packet);
        } catch (IOException e) {
            log.error("can not send udp message to agent: " + message);
            e.printStackTrace();
        }
    }

    public void send(byte[] message) {
        // send message to agent ap
        DatagramPacket packet = new DatagramPacket(message, message.length,
                                        this.ipAddress, this.AGENT_PORT);
        try {
            this.agentSocket.send(packet);
        } catch (IOException e) {
            log.error("can not send udp message to agent: " + message.toString());
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("Agent " + ipAddress.getHostAddress() + ", uprate="
                + Double.toString(upRate) + ", downrate=" + Double.toString(downRate)
                + ", clientNum=" + Integer.toString(getClientNum()));

        if (this.ofSwitch != null) {
            builder.append(", dpid=" + (ofSwitch.getId()).toString());
        }

        return builder.toString();
    }

    /**
     * response to the client-info messages from agent
     * 1) initialize client instance
     * 2) update client ip address info
     *
     * @param clientEthAddr, client MAC address in the messages
     * @param clientIpAddr, client IPv4 address
     * @return client, client instance corresponding to this info
     */
    Client receiveClientInfo(final MacAddress clientEthAddr, final IPv4Address clientIpAddr) {


        if (clientMap.containsKey(clientEthAddr)) { // update client info
		    Client client = clientMap.get(clientEthAddr);
		    if (!client.getIpAddress().equals(clientIpAddr)) {
		        client.setIpAddress(clientIpAddr);
		    }
		} else { // new client
		    Client client = new Client(clientEthAddr, clientIpAddr, this);
		    if (ofSwitch != null) {
		        client.setSwitch(ofSwitch);
		    }
		    clientMap.put(clientEthAddr, client);

		    log.info("New client connected {} -- {}, initializing it...", 
		            clientEthAddr, clientIpAddr);
		    
		    return client;
		}

        return null;
    }

    /**
     * response to the client-rate messages from agent
     *
     * @param clientEthAddr, client mac address
     * @param rate, client's byte rate of ip flows
     */
    Client receiveClientRate(final MacAddress clientEthAddr, final double uprate,
                            final double downrate) {

        if (clientMap.containsKey(clientEthAddr)) {
            Client clt = clientMap.get(clientEthAddr);
            clt.updateUpRate(uprate);
            clt.updateDownRate(downrate);
            // System.out.println(clt.toString());
            
            IOFSwitch sw = clt.getSwitch();
            // modify flow action to drop
            if (uprate >= RATE_THRESHOLD && sw != null) {

                log.info("FlowRate = {}bytes/s: suspicious flow, " +
                        "drop matched pkts", Double.toString(uprate));

                dropFlow(sw, clt, clientEthAddr);
            }
            
            return clt;
        } else {
            log.warn("Received uninilized Client rate info, checking with agent...");
            
            
            byte[] m = clientEthAddr.getBytes();
            byte[] signal = "ack".getBytes();
            byte[] message = new byte[m.length + signal.length];

            System.arraycopy(signal, 0, message, 0, signal.length);
            System.arraycopy(m, 0, message, signal.length, m.length);
            this.send(message);
            
            return null;
        }
    }
    
    /*
     *  ask agent to report current info of connected client
     *  
     *  this func is used to get client info if master starts later then agent
     */
    public void checkClients() {
    	log.info("Checking clients status on this agent...");
    	
    	byte[] message = "arp".getBytes(); // a -- to agent, rp -- report
    	send(message);
    }
    
    public void dropFlow(IOFSwitch sw, Client clt, MacAddress mac) {
    	
    	Match.Builder matchBuilder = sw.getOFFactory().buildMatch();
    	
    	matchBuilder.setExact(MatchField.ETH_SRC, mac)
    	            .setExact(MatchField.ETH_TYPE, EthType.IPv4)
    	            .setExact(MatchField.IPV4_SRC, clt.getIpAddress());
    	            
    	OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowModify();
    	// set no action to drop
        List<OFAction> actions = new ArrayList<OFAction>();
    
    	fmb.setCookie(U64.of(67));
    	fmb.setPriority(200);
        fmb.setOutPort(OFPort.ALL);
        fmb.setMatch(matchBuilder.build());
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setHardTimeout(0);
        fmb.setIdleTimeout(20);
        fmb.setActions(actions);
   
        // send flow_mod

        try {
            sw.write(fmb.build(), null);
        } catch (Exception e) {
            log.error("Failure to modify flow entries", e);
        }
    }
   


    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof APAgent))
            return false;

        if (obj == this)
            return true;

        APAgent that = (APAgent) obj;

        return (this.bssid.toLowerCase().equals(that.getBSSID().toLowerCase()));
    }


    @Override
    public int compareTo(Object o) {
        assert (o instanceof APAgent);

        if (this.bssid.toLowerCase().equals(((APAgent)o).getBSSID().toLowerCase()))
            return 0;

        if (this.downRate > ((APAgent)o).getDownRate())
            return 1;

        return -1;
    }
}
