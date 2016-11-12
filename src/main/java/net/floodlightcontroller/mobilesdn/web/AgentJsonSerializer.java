/**
 * 
 */
package net.floodlightcontroller.mobilesdn.web;

import java.io.IOException;

import net.floodlightcontroller.mobilesdn.APAgent;
import net.floodlightcontroller.mobilesdn.Client;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * @author Yanhe Liu <yanhe.liu@cs.helsinki.fi>
 *
 */
public class AgentJsonSerializer extends JsonSerializer<APAgent> {

    /**
     * Handles serialization for APAgent
     */
    @Override
    public void serialize(APAgent agent, JsonGenerator jGen,
            SerializerProvider serializer) throws IOException,
            JsonProcessingException {
        
        jGen.writeStartObject();
        
        jGen.writeStringField("ssid", agent.getSSID());
        jGen.writeStringField("bssid", agent.getBSSID());
        jGen.writeStringField("managedip", agent.getIpAddress().getHostAddress());
        jGen.writeStringField("auth", agent.getAuth());
        jGen.writeStringField("downbandwidth", Double.toString(agent.getDownlinkBW()));
        jGen.writeStringField("downrate", Double.toString(agent.getOFDownRate()));
        
        jGen.writeArrayFieldStart("client");
        int count = 0;
        for (Client clt : agent.getAllClients()) {
        	jGen.writeString(clt.getMacAddress().toString());
        	count++;
        }
        jGen.writeEndArray();
        
        jGen.writeNumberField("clientnum", count);
        
        jGen.writeEndObject();
    }
    
    
    /**
     * Tells SimpleModule that we are the serializer for APAgent
     */
    @Override
    public Class<APAgent> handledType() {
        return APAgent.class;
    }

}
