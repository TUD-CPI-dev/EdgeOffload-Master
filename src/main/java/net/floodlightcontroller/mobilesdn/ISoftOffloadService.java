/**
 * 
 */
package net.floodlightcontroller.mobilesdn;

import java.util.Collection;

import net.floodlightcontroller.core.module.IFloodlightService;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public interface ISoftOffloadService extends IFloodlightService {
    public Collection<APAgent> getAgents();
    
    public APAgent getAgent(String agentIp);
    
    public Client getClient(String clientMac);
}
