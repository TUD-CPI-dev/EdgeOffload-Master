/**
 * 
 */
package net.floodlightcontroller.mobilesdn.web;

import net.floodlightcontroller.mobilesdn.Client;
import net.floodlightcontroller.mobilesdn.ISoftOffloadService;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class ClientEntityResource extends ServerResource {
    @Get("json")
    public Client retrieve() {
        ISoftOffloadService sf = (ISoftOffloadService)getContext().getAttributes().get(ISoftOffloadService.class.getCanonicalName());
        
        String clientId = (String) getRequestAttributes().get("clientId");
        
        return sf.getClient(clientId);
    }
}
