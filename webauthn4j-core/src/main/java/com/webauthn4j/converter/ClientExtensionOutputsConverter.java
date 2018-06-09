package com.webauthn4j.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class ClientExtensionOutputsConverter {

    private final ObjectMapper jsonMapper = ObjectMapperUtil.createJSONMapper();

    public Map<String, ClientExtensionOutput> convert(byte[] value){
        return convert(new String(value, StandardCharsets.UTF_8));
    }

    public Map<String, ClientExtensionOutput> convert(String value){
        try {
            if(value == null){
                return null;
            }
            return jsonMapper.readValue(value, new TypeReference<Map<String, ClientExtensionOutput>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(Map<String, ClientExtensionOutput> value){
        try {
            if(value == null){
                return null;
            }
            return jsonMapper.writeValueAsString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(Map<String, ClientExtensionOutput> value){
        try {
            if(value == null){
                return new byte[0];
            }
            return jsonMapper.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
