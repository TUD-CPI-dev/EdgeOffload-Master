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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.mobilesdn.web.ClientJsonSerializer;

/**
 * Class for Wireless client:
 * used for recording and managing client info
 *
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
@JsonSerialize(using=ClientJsonSerializer.class)
public class Client implements Comparable<Object> {
    protected static Logger log = LoggerFactory.getLogger(Client.class);

    private final MacAddress hwAddress;
    private IPv4Address ipAddress;
    private String app = "trivial";
    private double upRate;
    private double downRate;
    private long ofUpBytes = 0;
    private long ofDownBytes = 0;
    
    private long connectTime;
    private long lastRecvTime = 0;

    private boolean isStatic = false;
    private boolean isBeingEvaluated = false;
    
    private IOFSwitch ofSwitch = null;      // not initialized
    private APAgent agent;
    // used to record nearby ap signal levels
    private Map<String, List<Integer>> apSignalLevelMap = new ConcurrentHashMap<String, List<Integer>>();
    private int apScanningTime = 0;

    private Timer switchTimer;

    // defaults
    static private final long SECONDS = 3 * 60 * 1000;
    private static final int DELAY = 6000; // 6000 milliseconds

    // currently not used anymore, for testing before
    private void initializeClientTimer() {

        switchTimer = new Timer();    // set the timer

        switchTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                // set up message data
                byte[] mac = hwAddress.getBytes();
                byte[] b1 = "c".getBytes();
                byte[] b2 = "switch|sdntest1|open|\n".getBytes();

                byte[] message = new byte[b1.length + b2.length + mac.length];

                System.arraycopy(b1, 0, message, 0, b1.length);
                System.arraycopy(mac, 0, message, b1.length, mac.length);
                System.arraycopy(b2, 0, message, b1.length + mac.length, b2.length);

                agent.send(message);
                log.info("Send message to agent for client switching");
            }
        }, SECONDS);
    }

    /**
     * construct a client instance
     *
     * @param hwAddress Client's hw address
     * @param ipv4Address Client's IPv4 address
     */
    public Client(MacAddress hwAddress, IPv4Address ipAddress, APAgent agt) {
        this.hwAddress = hwAddress;
        this.ipAddress = ipAddress;
        this.agent = agt;

        // initializeClientTimer();
        initConnectTime();
    }

    /**
     * construct a client instance
     *
     * @param hwAddress Client's hw address
     * @param ipv4Address Client's IPv4 address
     */
    public Client(String hwAddress, IPv4Address ipAddress, APAgent agt) throws UnknownHostException {
        this.hwAddress = MacAddress.of(hwAddress);
        this.ipAddress = ipAddress;
        this.agent = agt;

        // initializeClientTimer();
        initConnectTime();
    }

    /**
     * construct a client instance
     *
     * @param hwAddress Client's hw address
     * @param ipv4Address Client's IPv4 address
     */
    public Client(MacAddress hwAddress, IPv4Address ipAddress, IOFSwitch sw, APAgent agt) {
        this.hwAddress = hwAddress;
        this.ipAddress = ipAddress;
        this.ofSwitch = sw;
        this.agent = agt;

        // initializeClientTimer();
        initConnectTime();
    }

    /**
     * construct a client instance
     *
     * @param hwAddress Client's hw address
     * @param ipv4Address Client's IPv4 address
     */
    public Client(String hwAddress, IPv4Address ipAddress, IOFSwitch sw, APAgent agt) throws UnknownHostException {
        this.hwAddress = MacAddress.of(hwAddress);
        this.ipAddress = ipAddress;
        this.ofSwitch = sw;
        this.agent = agt;

        // initializeClientTimer();
        initConnectTime();
    }

    /**
     * Set the client's first connecting time
     */
    public void initConnectTime() {
        this.connectTime = System.currentTimeMillis();
    }

    /**
     * Get the client's first connecting time
     * @return this.connectTime
     */
    public long getConnectTime() {
        return this.connectTime;
    }

    /**
     * Get the client's MAC address.
     * @return
     */
    public MacAddress getMacAddress() {
        return this.hwAddress;
    }

    /**
     * Get the client's IP address.
     * @return
     */
    public IPv4Address getIpAddress() {
        return ipAddress;
    }

    /**
     * Set the client's IP address
     * @param addr
     */
    public void setIpAddress(IPv4Address addr) {
        this.ipAddress = addr;
    }

    /**
     * get client's uprate value
     * @return
     */
    public synchronized double getUpRate() {
        return this.upRate;
    }

    /**
     * get client's downrate value
     * @return
     */
    public synchronized double getDownRate() {
        return this.downRate;
    }

    /**
     * Set the client's up rate value
     * @param r
     */
    public synchronized void updateUpRate(double r) {
        if (upRate != 0) { // test whether this is explicitly initialized
            upRate = (upRate + r) / 2;
        } else {
            upRate = r;
        }
    }

    /**
     * Set the client's down rate value
     * @param r
     */
    public synchronized void updateDownRate(double r) {
        if (downRate != 0) { // // test whether this is explicitly initialized
            downRate = (r + downRate) / 2;
        } else {
            downRate = r;
        }
        
    }
    
    public synchronized long getOFUpBytes() {
    	return ofUpBytes;
    }
    
    public synchronized long getOFDownBytes() {
    	return ofDownBytes;
    }
    
    public synchronized void updateOFUpBytes(long x) {
    	ofUpBytes = x;
    }
    
    public synchronized void updateOFDownBytes(long x) {
    	ofDownBytes = x;
    }
    
    public synchronized void rateReset() {
    	upRate = 0;
    	downRate = 0;
    }

    /**
     * get client's corresponding openflow switch instance
     * @return
     */
    public IOFSwitch getSwitch() {
        return this.ofSwitch;
    }

    /**
     * Set the client's association openflow switch instance
     *
     * @param sw
     */
    public void setSwitch(IOFSwitch sw) {
        this.ofSwitch = sw;
    }

    /**
     * Set the client's running application
     *
     * @param app
     */
    public void setApp(String app) {
        this.app = app;
    }

    /**
     * Get the client's running app
     * @return app
     */
    public String getApp() {
        return app;
    }

    /**
     * Get the client's corresponding AP Agent.
     * @return
     */
    public APAgent getAgent() {
        return agent;
    }

    /**
     * clear the task for the timer
     */
    public void cancelTask() {
        this.switchTimer.cancel();
        this.switchTimer.purge();
    }
    
    public synchronized void startOffloadingEvaluation() {
    	isBeingEvaluated = true;
    }
    
    public synchronized void finishOffloadingEvaluation() {
    	isBeingEvaluated = false;
    }
    
    public synchronized boolean isBeningEvaluated() {
    	return isBeingEvaluated;
    }
    
    /**
     * update current record of ap signal levels
     * the input follows this type: ssid1&bssid1&level1|ssid2&bssid2&level2|...
     *
     * @param fields: this is the context collect from the client
     */
    public synchronized void updateSignalInfo(String[] fields) {
        long currTime = System.currentTimeMillis();
        if (lastRecvTime != 0 && currTime - lastRecvTime >= DELAY) {
            apScanningTime = 0;
            apSignalLevelMap.clear();
        } 
        lastRecvTime = currTime; // update
        
        if (apScanningTime == 3) { // clear old data, now the program runs in a simple way
            apSignalLevelMap.clear();
            apScanningTime = 0;
        }
        
        apScanningTime++;  // add one for every time it receive scanning results
        
        for (int i = 0; i < fields.length; i++) {
            String[] info = fields[i].split("&");
            // String ssid = info[0];
            String bssid = info[1].toLowerCase();
            int level = Integer.parseInt(info[2]);

            if (apSignalLevelMap.containsKey(bssid)) {
                // make sure every bssid list has the same size
                // use the same value for missing ones
                int size = apSignalLevelMap.get(bssid).size();
                for (int j = size; j < (apScanningTime - 1); j++) {
                    apSignalLevelMap.get(bssid).add(level);
                }
                apSignalLevelMap.get(bssid).add(level); 
            } else {
                List<Integer> signalLevelList = new ArrayList<Integer>();
                for (int j = 1; j < apScanningTime; j++) {
                    // set the same value for missing ones
                    signalLevelList.add(level);
                }
                signalLevelList.add(level);
                apSignalLevelMap.put(bssid, signalLevelList);
            }
        }
        
        // log.info("Update signal level info -- time " + apScanningTime);
    }
    
    public boolean isStatic() {
        return isStatic;
    }
    
    public void updateStaticFlag(boolean t) {
        isStatic = t;
    }
    
    public boolean isReadyToOffload() {
        boolean result = false;
        if (isStatic || getAPScanningTime() == 3) {
            result = true;
        }
        
        return result;
    }
    
    public synchronized Set<String> getNearbyAPSet() {
        return apSignalLevelMap.keySet();
    }
    
    public synchronized int getAPScanningTime() {
        return apScanningTime;
    }
    
    /**
     * calculate client mobility metric
     *
     * @param bssid
     */
    public double mobilityPrediction(String bssid) {
        List<Integer> signalLevelList = apSignalLevelMap.get(bssid);
        double mobility;
        
        if (signalLevelList == null) {
            throw new RuntimeException("invalid parameter for evaluation");
        }
        
        int s1 = signalLevelList.get(0);
        int s2 = signalLevelList.get(1);
        int s3 = signalLevelList.get(2);
        
        if (s1 <= s2 && s2 <= s3 && s3 - s1 > 3) { // definitely getting closer
            mobility = 1;
        } else if (s1 >= s2 && s2 >= s3 && s1 - s3 > 3) { // getting further
            mobility = 0.7;
        } else if (s1 <= s2 && s1 - s3 > 3) { // signal level first increases, but finally drops
            mobility = 0.8;
        } else if (s1 > s2 && s3 - s1 > 3) { // signal level first drops, but finally increases
            mobility = 0.9;
        } else {  // moving direction is not very clear
            mobility = 0.85;
        }
        
        log.info("mobility records for ap " + bssid + ": " + s1 + ", " + s2 + ", " + s3);
        log.info("mobility predition for ap " + bssid + ": " + mobility);
        return mobility;
    }
    
    public double signalEvaluation(String bssid) {
        List<Integer> signalLevelList = apSignalLevelMap.get(bssid);
        int s;
        double result;
        
        if (signalLevelList == null) {
            throw new java.util.NoSuchElementException("invalid parameter for evaluation");
        }
        
        if (isStatic()) {
            s = signalLevelList.get(0);
            result = 1 - Math.exp((-1.0 / 3.0) * (s + 73));
        } else {
            s = signalLevelList.get(2);
            result = mobilityPrediction(bssid) * (1- Math.exp((-1.0 / 3.0) * (s + 73)));
        }
        
        
        log.info("signal evaluation for ap " + bssid + ": signalLevel=" + s + ", result=" + result);
        return result;
    }
    
    

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("Client " + hwAddress.toString() + ", ipAddr="
                + ipAddress.toString() + ", uprate="
                + Double.toString(upRate) + ", downrate=" + Double.toString(downRate)
                + ", dpid=" + (ofSwitch.getId()).toString());

        return builder.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Client))
            return false;

        if (obj == this)
            return true;

        Client that = (Client) obj;

        return (this.hwAddress.equals(that.getMacAddress()));
    }


    @Override
    public int compareTo(Object o) {
        assert (o instanceof Client);

        if (this.hwAddress.getLong() == ((Client)o).getMacAddress().getLong())
            return 0;

        if (this.hwAddress.getLong() > ((Client)o).getMacAddress().getLong())
            return 1;

        return -1;
    }

}
