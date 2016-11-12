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

// import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * record switch and agent mapping here;
 * this class is just a wrapper for corresponding HashMap, and not used yet
 *
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class NetworkManager {
    private Map<Long, List<APAgent>> swToApAgentMap = new ConcurrentHashMap<Long, List<APAgent>>();

    public NetworkManager() {
        // initializing
    }

    public boolean containsSwitch(long swId) {
        return swToApAgentMap.containsKey(swId);
    }

    public void putSwitch(long swId, List<APAgent> agentList) {
        swToApAgentMap.put(swId, agentList);
    }

    public List<APAgent> getAssociatedAgent(long swId) {
        return swToApAgentMap.get(swId);
    }

    public int getAgentNum(long swId) {
        return swToApAgentMap.size();
    }

    public void removeSwitch(long swId) {
        swToApAgentMap.remove(swId);
    }

    public void removeAllSwitches() {
        swToApAgentMap.clear();
    }

    public boolean isSwitchMapEmpty() {
        return swToApAgentMap.isEmpty();
    }
}
