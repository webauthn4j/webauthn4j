package com.webauthn4j.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;

public class ClientExtensionOutputsConverter {

    private final ObjectMapper jsonMapper = ObjectMapperUtil.createJSONMapper();

    public Map<ExtensionIdentifier, ClientExtensionOutput> convert(byte[] value){
        try {
            if(value == null){
                return null;
            }
            return jsonMapper.readValue(value, new TypeReference<Map<ExtensionIdentifier, ClientExtensionOutput>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(Map<ExtensionIdentifier, ClientExtensionOutput> value){
        try {
            if(value == null){
                return null;
            }
            return jsonMapper.writeValueAsString(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(Map<ExtensionIdentifier, ClientExtensionOutput> value){
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
