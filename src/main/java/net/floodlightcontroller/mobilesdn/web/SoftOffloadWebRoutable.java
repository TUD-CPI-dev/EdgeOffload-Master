/**
 * 
 */
package net.floodlightcontroller.mobilesdn.web;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class SoftOffloadWebRoutable implements RestletRoutable {

    /* (non-Javadoc)
     * @see net.floodlightcontroller.restserver.RestletRoutable#getRestlet(org.restlet.Context)
     */
    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        // router.attach("/", DeviceResource.class);
        router.attach("/agents/json", AgentResource.class);
        router.attach("/agent/{agentId}/json", AgentEntityResource.class);
        router.attach("/client/{clientId}/json", ClientEntityResource.class);
        return router;
    }

    /* (non-Javadoc)
     * @see net.floodlightcontroller.restserver.RestletRoutable#basePath()
     */
    @Override
    public String basePath() {
        return "/wm/softoffload";
    }

}
