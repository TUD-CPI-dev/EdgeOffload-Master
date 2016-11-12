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
public class ClientJsonSerializer extends JsonSerializer<Client> {

    /**
     * Handles serialization for APAgent
     */
    @Override
    public void serialize(Client clt, JsonGenerator jGen,
            SerializerProvider serializer) throws IOException,
            JsonProcessingException {
        
        jGen.writeStartObject();
        
        jGen.writeStringField("mac", clt.getMacAddress().toString());
        jGen.writeStringField("ip", clt.getIpAddress().toString());
        jGen.writeStringField("downrate", Double.toString(clt.getDownRate()));
        
        jGen.writeObjectFieldStart("agent");
        jGen.writeStringField("ssid", clt.getAgent().getSSID());
        jGen.writeStringField("bssid", clt.getAgent().getBSSID());
        jGen.writeStringField("ip", clt.getAgent().getIpAddress().getHostAddress());
        jGen.writeEndObject();
        
        jGen.writeEndObject();
    }
    
    
    /**
     * Tells SimpleModule that we are the serializer for APAgent
     */
    @Override
    public Class<Client> handledType() {
        return Client.class;
    }

}
