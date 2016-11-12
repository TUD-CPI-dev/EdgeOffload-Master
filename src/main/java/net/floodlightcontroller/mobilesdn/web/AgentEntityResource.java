/**
 * 
 */
package net.floodlightcontroller.mobilesdn.web;

import net.floodlightcontroller.mobilesdn.APAgent;
import net.floodlightcontroller.mobilesdn.ISoftOffloadService;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class AgentEntityResource extends ServerResource {
    @Get("json")
    public APAgent retrieve() {
        ISoftOffloadService sf = (ISoftOffloadService)getContext().getAttributes().get(ISoftOffloadService.class.getCanonicalName());
        
        String agentId = (String) getRequestAttributes().get("agentId");
        
        return sf.getAgent(agentId);
    }
}
