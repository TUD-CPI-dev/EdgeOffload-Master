/**
 * 
 */
package net.floodlightcontroller.mobilesdn.web;

import java.util.Collection;

import net.floodlightcontroller.mobilesdn.APAgent;
import net.floodlightcontroller.mobilesdn.ISoftOffloadService;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class AgentResource extends ServerResource {
    @Get("json")
    public Collection<APAgent> retrieve() {
        ISoftOffloadService sf = (ISoftOffloadService)getContext().getAttributes().get(ISoftOffloadService.class.getCanonicalName());
        return sf.getAgents();
    }
}
